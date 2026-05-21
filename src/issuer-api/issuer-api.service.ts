import { Injectable, Logger } from '@nestjs/common';
import { SDJwtInstance } from '@sd-jwt/core';
import type { SdJwtPayload } from '@sd-jwt/core';
import type { Request } from 'express';
import { CryptoService } from '../crypto/crypto.service';
import { KeysService } from '../keys/keys.service';
import { SigningKeyEntity } from '../keys/entities/signing-key.entity';
import { StatusListService } from '../status-list/status-list.service';
import { IssueCredentialDto } from './dto/issue-credential.dto';

/**
 * Résultat de la vérification d'un SD-JWT-VC.
 */
export interface VerifyResult {
	valid: boolean;
	payload?: Record<string, unknown>;
	error?: string;
}

/**
 * Service d'émission et de vérification des SD-JWT-VC.
 *
 * Maintient un cache d'instances SDJwtInstance par clé de signature
 * pour éviter de recréer les closures à chaque requête.
 */
@Injectable()
export class IssuerApiService {
	private readonly logger = new Logger(IssuerApiService.name);

	/**
	 * Cache des instances SDJwtInstance, indexées par l'identifiant UUID
	 * de la clé de signature. Recréées si la clé change.
	 */
	private readonly sdjwtInstances = new Map<
		string,
		SDJwtInstance<SdJwtPayload>
	>();

	constructor(
		private readonly keysService: KeysService,
		private readonly crypto: CryptoService,
		private readonly statusList: StatusListService,
	) {}

	// ─────────────────────────────────────────────
	// Clé publique
	// ─────────────────────────────────────────────

	/**
	 * Retourne la clé publique d'une clé de signature.
	 *
	 * @param signingKey - La clé de signature
	 * @param format - "jwk" pour le JWK brut, "did-jwk" pour le format did:jwk:...
	 */
	getPublicKey(
		signingKey: SigningKeyEntity,
		format: 'jwk' | 'did-jwk' = 'jwk',
	): Record<string, string> | string {
		const publicJwk = this.keysService.getPublicJwk(signingKey);
		if (format === 'did-jwk') {
			return this.crypto.buildDidJwk(publicJwk);
		}
		return publicJwk;
	}

	// ─────────────────────────────────────────────
	// Émission d'un SD-JWT-VC
	// ─────────────────────────────────────────────

	/**
	 * Émet un SD-JWT-VC signé avec la clé de signature indiquée.
	 *
	 * Flux :
	 * 1. Allouer un index dans la liste de statut
	 * 2. Construire le payload JWT standard + claims personnalisés
	 * 3. Construire le frame de divulgation sélective
	 * 4. Signer via SDJwtInstance
	 *
	 * @param signingKey - La clé utilisée pour signer le credential
	 * @param dto - Les données du credential à émettre
	 * @param req - Requête HTTP (pour construire l'URL de la liste de statut)
	 * @returns Le token SD-JWT-VC compact
	 */
	async issueCredential(
		signingKey: SigningKeyEntity,
		dto: IssueCredentialDto,
		req: Request,
	): Promise<string> {
		const jti = this.crypto.generateToken();
		const publicJwk = this.keysService.getPublicJwk(signingKey);
		const issuerDid = this.crypto.buildDidJwk(publicJwk);

		// Allouer un index dans la liste de statut
		const status = await this.statusList.allocateIndex(signingKey, jti);

		// Construire l'URL de la liste de statut (absolue, basée sur la requête entrante)
		const baseUrl = `${req.protocol}://${req.get('host')}`;
		const statusUri = `${baseUrl}/api/${signingKey.identifier}/credential/status`;

		// Construire le payload complet du SD-JWT-VC
		const payload: Record<string, unknown> = {
			iss: issuerDid,
			iat: Math.floor(Date.now() / 1000),
			...(dto.exp ? { exp: dto.exp } : {}),
			vct: dto.vct,
			...(dto.subject ? { sub: dto.subject } : {}),
			jti,
			// Référence à la liste de statut (IETF Token Status List)
			status: {
				status_list: {
					idx: status.statusListIndex,
					uri: statusUri,
				},
			},
			// Claims personnalisés du credential (flat)
			...dto.claims,
		};

		// Frame de divulgation sélective : les champs listés seront des disclosures.
		// Cast nécessaire car le type DisclosureFrame est strict sur les keyof Payload.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const disclosureFrame = { _sd: dto.disclosableClaims } as any;

		// Obtenir ou créer l'instance SDJwt pour cette clé
		const sdjwt = this.getSdjwtInstance(signingKey);

		const credential = await sdjwt.issue(
			payload as SdJwtPayload,
			disclosureFrame,
			{ header: { alg: 'EdDSA', typ: 'vc+sd-jwt' } },
		);

		this.logger.log(
			`Credential émis : jti=${jti}, clé=${signingKey.identifier}, ` +
				`statusIndex=${status.statusListIndex}`,
		);

		return credential;
	}

	// ─────────────────────────────────────────────
	// Vérification d'un SD-JWT-VC
	// ─────────────────────────────────────────────

	/**
	 * Vérifie la signature et la structure d'un SD-JWT-VC.
	 *
	 * Note : la vérification de révocation (consultation de la liste de statut)
	 * est laissée au vérificateur externe, conformément au protocole.
	 *
	 * @param signingKey - La clé de signature attendue (issuer)
	 * @param token - Le token SD-JWT-VC à vérifier
	 */
	async verifyCredential(
		signingKey: SigningKeyEntity,
		token: string,
	): Promise<VerifyResult> {
		try {
			const sdjwt = this.getSdjwtInstance(signingKey);

			// Vérifier la signature et obtenir le payload décodé
			const result = await sdjwt.verify(token);

			return {
				valid: true,
				payload: result.payload as Record<string, unknown>,
			};
		} catch (error) {
			this.logger.warn(
				`Vérification échouée pour clé=${signingKey.identifier} : ${error instanceof Error ? error.message : String(error)}`,
			);
			return {
				valid: false,
				error:
					error instanceof Error
						? error.message
						: 'Vérification échouée',
			};
		}
	}

	// ─────────────────────────────────────────────
	// Gestion du cache SDJwtInstance
	// ─────────────────────────────────────────────

	/**
	 * Retourne une instance SDJwtInstance pour une clé de signature.
	 * L'instance est mise en cache par ID de clé.
	 *
	 * Chaque instance est construite avec des closures sur les JWK de la clé,
	 * capturant la clé privée en mémoire uniquement pendant la durée de vie
	 * du cache (réinitialisé au redémarrage).
	 */
	private getSdjwtInstance(
		signingKey: SigningKeyEntity,
	): SDJwtInstance<SdJwtPayload> {
		if (this.sdjwtInstances.has(signingKey.id)) {
			return this.sdjwtInstances.get(signingKey.id)!;
		}

		// Déchiffrer les JWK une fois pour construire l'instance
		const privateJwk = this.keysService.getPrivateJwk(signingKey);
		const publicJwk = this.keysService.getPublicJwk(signingKey);

		const instance = new SDJwtInstance<SdJwtPayload>({
			// Signataire : utilise la clé privée déchiffrée
			signer: (data: string) => this.crypto.signWithKey(data, privateJwk),
			// Vérificateur : utilise la clé publique
			verifier: (data: string, sig: string) =>
				Promise.resolve(
					this.crypto.verifyWithKey(data, sig, publicJwk),
				),
			signAlg: 'EdDSA',
			hasher: (data: string, alg: string) => this.crypto.hash(data, alg),
			hashAlg: 'sha-256',
			saltGenerator: () => this.crypto.generateSalt(),
		});

		this.sdjwtInstances.set(signingKey.id, instance);
		return instance;
	}
}
