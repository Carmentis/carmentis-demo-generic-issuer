import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as zlib from 'zlib';
import { DataSource, Repository } from 'typeorm';
import { CryptoService } from '../crypto/crypto.service';
import { KeysService } from '../keys/keys.service';
import { SigningKeyEntity } from '../keys/entities/signing-key.entity';
import { CredentialStatusEntity } from './entities/credential-status.entity';

/**
 * Service de gestion de la liste de statut des credentials.
 *
 * Implémentation basée sur le brouillon IETF Token Status List
 * (draft-ietf-oauth-status-list) : vecteur de bits gzip-compressé,
 * encodé en base64url, signé dans un JWT.
 *
 * bit = 0 → credential valide
 * bit = 1 → credential révoqué
 */
@Injectable()
export class StatusListService {
	private readonly logger = new Logger(StatusListService.name);

	constructor(
		@InjectRepository(CredentialStatusEntity)
		private readonly statusRepo: Repository<CredentialStatusEntity>,
		private readonly dataSource: DataSource,
		private readonly keysService: KeysService,
		private readonly crypto: CryptoService,
	) {}

	/**
	 * Alloue un index dans la liste de statut pour un nouveau credential.
	 * Opération atomique : incrémente statusListCurrent dans une transaction.
	 *
	 * @param signingKey - La clé de signature émettrice
	 * @param credentialId - Le jti du credential (pour traçabilité)
	 * @returns L'entité CredentialStatus créée
	 */
	async allocateIndex(
		signingKey: SigningKeyEntity,
		credentialId: string,
	): Promise<CredentialStatusEntity> {
		return this.dataSource.transaction(async (manager) => {
			const keyRepo = manager.getRepository(SigningKeyEntity);

			// Lire le compteur courant
			const key = await keyRepo.findOne({ where: { id: signingKey.id } });
			if (!key) {
				throw new Error(`Clé introuvable : ${signingKey.id}`);
			}

			const index = key.statusListCurrent;
			if (index >= key.statusListSize) {
				throw new Error(
					`La liste de statut de la clé "${key.identifier}" est pleine (${key.statusListSize} entrées max)`,
				);
			}

			// UPDATE atomique conditionnel : n'incrémente que si la valeur n'a pas changé.
			// SQLite sérialise les écritures par connexion, ce qui suffit ici.
			// Le résultat affected = 0 signifie qu'une concurrence a modifié la valeur
			// entre le SELECT et l'UPDATE — on lève une erreur explicite.
			const result = await keyRepo
				.createQueryBuilder()
				.update(SigningKeyEntity)
				.set({ statusListCurrent: index + 1 })
				.where('id = :id AND statusListCurrent = :expected', {
					id: key.id,
					expected: index,
				})
				.execute();

			if (result.affected === 0) {
				throw new Error(
					'Conflit d\'allocation d\'index de statut : réessayez l\'opération',
				);
			}

			// Créer l'entrée de statut
			const statusRepo = manager.getRepository(CredentialStatusEntity);
			const status = statusRepo.create({
				signingKeyId: key.id,
				statusListIndex: index,
				isRevoked: false,
				credentialId,
				revokedAt: null,
			});

			return statusRepo.save(status);
		});
	}

	/**
	 * Révoque un credential par son index dans la liste de statut.
	 *
	 * @param statusListIndex - Index dans la liste de statut
	 * @param signingKeyId - UUID de la clé de signature
	 */
	async revokeByIndex(
		statusListIndex: number,
		signingKeyId: string,
	): Promise<void> {
		await this.statusRepo.update(
			{ statusListIndex, signingKeyId },
			{ isRevoked: true, revokedAt: new Date() },
		);
		this.logger.log(
			`Credential révoqué : index=${statusListIndex}, clé=${signingKeyId}`,
		);
	}

	/**
	 * Révoque un credential par son identifiant (jti).
	 *
	 * @param credentialId - jti du credential
	 * @param signingKeyId - UUID de la clé de signature
	 */
	async revokeByCredentialId(
		credentialId: string,
		signingKeyId: string,
	): Promise<void> {
		await this.statusRepo.update(
			{ credentialId, signingKeyId },
			{ isRevoked: true, revokedAt: new Date() },
		);
		this.logger.log(
			`Credential révoqué par jti : jti=${credentialId}, clé=${signingKeyId}`,
		);
	}

	/**
	 * Construit et retourne le JWT de liste de statut pour une clé de signature.
	 *
	 * Format de réponse : application/statuslist+jwt
	 * Le JWT contient un claim "lst" avec le vecteur de bits compressé.
	 *
	 * @param signingKey - La clé de signature
	 * @returns JWT compact signé
	 */
	async buildStatusListJwt(signingKey: SigningKeyEntity): Promise<string> {
		// Récupérer tous les statuts pour cette clé
		const statuses = await this.statusRepo.find({
			where: { signingKeyId: signingKey.id },
		});

		// Construire le vecteur de bits (1 bit par credential)
		const byteCount = Math.ceil(signingKey.statusListSize / 8);
		const bitArray = new Uint8Array(byteCount);

		for (const status of statuses) {
			if (status.isRevoked) {
				const byteIndex = Math.floor(status.statusListIndex / 8);
				const bitIndex = status.statusListIndex % 8;
				bitArray[byteIndex] |= 1 << bitIndex;
			}
		}

		// Compresser avec gzip et encoder en base64url
		const compressed = zlib.deflateSync(Buffer.from(bitArray), {
			level: 9,
		});
		//const compressed = zlib.gzipSync(Buffer.from(bitArray));
		const encoded = compressed.toString('base64url');

		// Construire le payload JWT de liste de statut
		const publicJwk = this.keysService.getPublicJwk(signingKey);
		const issuerDid = this.crypto.buildDidJwk(publicJwk);
		const privateJwk = this.keysService.getPrivateJwk(signingKey);

		const now = Math.floor(Date.now() / 1000);
		const alg = signingKey.algorithm ?? this.crypto.algForJwk(publicJwk);
		const header = { alg, typ: 'statuslist+jwt' };
		const payload = {
			iss: issuerDid,
			iat: now,
			exp: now + 3600, // Valable 1 heure
			lst: encoded,
			bits: 1,
			statusList: {
				bits: 1,
				lst: encoded,
			},
			status_list: {
				bits: 1,
				lst: encoded,
			},
		};

		// Signer le JWT manuellement (même approche que pour le SD-JWT-VC)
		return this.signJwt(header, payload, privateJwk);
	}

	/**
	 * Signe un JWT compact avec une clé Ed25519 (JWK).
	 * Utilisé en interne pour signer la liste de statut.
	 */
	private async signJwt(
		header: Record<string, string>,
		payload: Record<string, unknown>,
		privateJwk: Record<string, unknown>,
	): Promise<string> {
		const headerB64 = Buffer.from(JSON.stringify(header)).toString(
			'base64url',
		);
		const payloadB64 = Buffer.from(JSON.stringify(payload)).toString(
			'base64url',
		);
		const signingInput = `${headerB64}.${payloadB64}`;

		// Signature adaptée au type de clé (Ed25519/EC/RSA)
		const sigB64 = await this.crypto.signWithKey(signingInput, privateJwk);
		return `${signingInput}.${sigB64}`;
	}
}
