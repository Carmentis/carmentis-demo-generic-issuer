import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { Repository } from 'typeorm';
import { ApiKeyEntity } from './entities/api-key.entity';

/**
 * Service de gestion des clés d'API.
 *
 * Les clés d'API permettent d'appeler l'endpoint /api/:name/issue.
 * Chaque clé est associée à une clé de signature spécifique.
 *
 * Sécurité :
 * - La valeur en clair n'est jamais stockée
 * - Seul un hash bcrypt et un préfixe de 8 caractères sont conservés
 * - La validation utilise le préfixe pour réduire les candidats, puis bcrypt.compare
 */
@Injectable()
export class ApiKeyService {
	private readonly logger = new Logger(ApiKeyService.name);

	constructor(
		@InjectRepository(ApiKeyEntity)
		private readonly apiKeyRepo: Repository<ApiKeyEntity>,
	) {}

	/**
	 * Crée une nouvelle clé d'API pour une clé de signature donnée.
	 *
	 * @returns L'entité sauvegardée ET la valeur en clair de la clé (à afficher une seule fois)
	 */
	async createApiKey(
		signingKeyId: string,
		label: string,
	): Promise<{ entity: ApiKeyEntity; plainKey: string }> {
		// Générer une clé aléatoire de 32 octets encodée en base64url
		const plainKey = crypto.randomBytes(32).toString('base64url');
		const keyPrefix = plainKey.substring(0, 8);
		const keyHash = await bcrypt.hash(plainKey, 10);

		const entity = this.apiKeyRepo.create({
			label,
			keyHash,
			keyPrefix,
			signingKeyId,
			isRevoked: false,
		});

		const saved = await this.apiKeyRepo.save(entity);
		this.logger.log(
			`Clé d'API créée pour signingKey=${signingKeyId}, label="${label}"`,
		);
		return { entity: saved, plainKey };
	}

	/**
	 * Retourne toutes les clés d'API d'une clé de signature.
	 */
	async findAllBySigningKey(signingKeyId: string): Promise<ApiKeyEntity[]> {
		return this.apiKeyRepo.find({
			where: { signingKeyId },
			order: { createdAt: 'ASC' },
		});
	}

	/**
	 * Révoque une clé d'API (la désactive sans la supprimer).
	 */
	async revokeApiKey(id: string): Promise<void> {
		await this.apiKeyRepo.update(id, {
			isRevoked: true,
			revokedAt: new Date(),
		});
		this.logger.log(`Clé d'API révoquée : ${id}`);
	}

	/**
	 * Valide une clé d'API en clair.
	 *
	 * Algorithme :
	 * 1. Extraire le préfixe (8 premiers caractères)
	 * 2. Chercher en base les clés non révoquées avec ce préfixe
	 * 3. Pour chaque candidat, comparer avec bcrypt
	 *
	 * @param rawKey - Clé d'API en clair (telle que transmise dans le header HTTP)
	 * @returns L'entité ApiKey avec sa relation signingKey, ou null si invalide
	 */
	async validateApiKey(rawKey: string): Promise<ApiKeyEntity | null> {
		if (!rawKey || rawKey.length < 8) return null;

		const prefix = rawKey.substring(0, 8);

		// Récupérer les candidats avec la relation signingKey pour vérifier l'identifier
		const candidates = await this.apiKeyRepo.find({
			where: { keyPrefix: prefix, isRevoked: false },
			relations: { signingKey: true },
		});

		for (const candidate of candidates) {
			const match = await bcrypt.compare(rawKey, candidate.keyHash);
			if (match) return candidate;
		}

		return null;
	}
}
