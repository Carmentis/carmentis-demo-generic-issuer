import {
	ConflictException,
	Injectable,
	Logger,
	NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CryptoService } from '../crypto/crypto.service';
import { SigningKeyEntity } from './entities/signing-key.entity';

/**
 * Service de gestion des paires de clés de signature Ed25519.
 *
 * Chaque clé est identifiée par un slug unique (identifier) utilisé dans les URL.
 * La clé privée est stockée chiffrée (AES-256-GCM) en base de données.
 */
@Injectable()
export class KeysService {
	private readonly logger = new Logger(KeysService.name);

	constructor(
		@InjectRepository(SigningKeyEntity)
		private readonly keyRepo: Repository<SigningKeyEntity>,
		private readonly crypto: CryptoService,
	) {}

	/**
	 * Crée une nouvelle paire de clés Ed25519 et la persiste en base.
	 *
	 * @param name - Nom lisible (ex: "Clé Université")
	 * @param identifier - Slug URL-safe unique (ex: "universite-paris")
	 * @throws ConflictException si l'identifier est déjà utilisé
	 */
	async createKey(
		name: string,
		identifier: string,
	): Promise<SigningKeyEntity> {
		// Vérifier l'unicité de l'identifier
		const existing = await this.keyRepo.findOne({ where: { identifier } });
		if (existing) {
			throw new ConflictException(
				`L'identifier "${identifier}" est déjà utilisé`,
			);
		}

		// Générer la paire de clés Ed25519
		const { publicJwk, privateJwk } =
			await this.crypto.generateEd25519KeyPair();

		// Chiffrer la clé privée avant persistance
		const encrypted = this.crypto.encryptPrivateKey(
			JSON.stringify(privateJwk),
		);

		const entity = this.keyRepo.create({
			name,
			identifier,
			encryptedPrivateKey: encrypted.ciphertext,
			encryptionIv: encrypted.iv,
			encryptionTag: encrypted.tag,
			publicKeyJwk: JSON.stringify(publicJwk),
		});

		const saved = await this.keyRepo.save(entity);
		this.logger.log(`Clé créée : ${identifier} (id=${saved.id})`);
		return saved;
	}

	/**
	 * Retourne toutes les clés de signature (sans données sensibles).
	 */
	async findAll(): Promise<SigningKeyEntity[]> {
		return this.keyRepo.find({ order: { createdAt: 'ASC' } });
	}

	/**
	 * Retourne une clé par son identifiant UUID interne.
	 * @throws NotFoundException si introuvable
	 */
	async findById(id: string): Promise<SigningKeyEntity> {
		const key = await this.keyRepo.findOne({
			where: { id },
			relations: { apiKeys: true },
		});
		if (!key) {
			throw new NotFoundException(`Clé introuvable : ${id}`);
		}
		return key;
	}

	/**
	 * Retourne une clé par son slug identifier (utilisé dans les routes /api/:name).
	 * @throws NotFoundException si introuvable
	 */
	async findByIdentifier(identifier: string): Promise<SigningKeyEntity> {
		const key = await this.keyRepo.findOne({ where: { identifier } });
		if (!key) {
			throw new NotFoundException(
				`Aucune clé trouvée pour l'identifier "${identifier}"`,
			);
		}
		return key;
	}

	/**
	 * Déchiffre et retourne le JWK privé d'une clé.
	 * À utiliser uniquement au moment de la signature.
	 *
	 * @returns JWK privé en tant qu'objet JavaScript
	 */
	getPrivateJwk(entity: SigningKeyEntity): Record<string, string> {
		const json = this.crypto.decryptPrivateKey({
			ciphertext: entity.encryptedPrivateKey,
			iv: entity.encryptionIv,
			tag: entity.encryptionTag,
		});
		return JSON.parse(json) as Record<string, string>;
	}

	/**
	 * Retourne le JWK public d'une clé en tant qu'objet JavaScript.
	 */
	getPublicJwk(entity: SigningKeyEntity): Record<string, string> {
		return JSON.parse(entity.publicKeyJwk) as Record<string, string>;
	}

	/**
	 * Supprime une clé de signature et toutes ses dépendances (cascade).
	 */
	async deleteKey(id: string): Promise<void> {
		const key = await this.findById(id);
		await this.keyRepo.remove(key);
		this.logger.log(`Clé supprimée : ${id}`);
	}
}
