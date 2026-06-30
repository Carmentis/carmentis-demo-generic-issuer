import { Injectable } from '@nestjs/common';
import { AdminAuthService } from '../auth/admin-auth.service';
import { ApiKeyService } from '../auth/api-key.service';
import { KeysService } from '../keys/keys.service';
import { CryptoService } from '../crypto/crypto.service';

/**
 * Service d'orchestration pour l'interface d'administration.
 * Délègue aux services spécialisés et formate les données pour les vues HBS.
 */
@Injectable()
export class AdminService {
	constructor(
		private readonly keysService: KeysService,
		private readonly apiKeyService: ApiKeyService,
		private readonly adminAuth: AdminAuthService,
		private readonly crypto: CryptoService,
	) {}

	/**
	 * Retourne toutes les clés avec le nombre de clés d'API associées.
	 */
	async getKeysWithStats() {
		const keys = await this.keysService.findAll();
		const result: Record<string, unknown>[] = [];

		for (const key of keys) {
			const apiKeys = await this.apiKeyService.findAllBySigningKey(
				key.id,
			);
			const publicJwk = this.keysService.getPublicJwk(key);
			result.push({
				...key,
				algorithm: key.algorithm ?? this.crypto.algForJwk(publicJwk),
				apiKeyCount: apiKeys.length,
				activeApiKeyCount: apiKeys.filter((k) => !k.isRevoked).length,
				publicJwk,
				didJwk: this.crypto.buildDidJwk(publicJwk),
			});
		}

		return result;
	}

	/**
	 * Retourne une clé avec ses clés d'API et sa représentation publique.
	 */
	async getKeyDetail(id: string) {
		const key = await this.keysService.findById(id);
		const apiKeys = await this.apiKeyService.findAllBySigningKey(id);
		const publicJwk = this.keysService.getPublicJwk(key);

		return {
			...key,
			apiKeys,
			algorithm: key.algorithm ?? this.crypto.algForJwk(publicJwk),
			hasCertificate: Array.isArray(publicJwk.x5c),
			publicJwkFormatted: JSON.stringify(publicJwk, null, 2),
			didJwk: this.crypto.buildDidJwk(publicJwk),
			statusListPercent: Math.round(
				(key.statusListCurrent / key.statusListSize) * 100,
			),
		};
	}

	/**
	 * Crée une nouvelle clé de signature.
	 * Valide le format de l'identifier (slug).
	 *
	 * @throws Error si l'identifier contient des caractères invalides
	 */
	async createKey(name: string, identifier: string) {
		// Valider le format slug : lettres minuscules, chiffres, tirets uniquement
		if (!/^[a-z0-9-]+$/.test(identifier)) {
			throw new Error(
				"L'identifier ne peut contenir que des lettres minuscules, des chiffres et des tirets",
			);
		}
		return this.keysService.createKey(name, identifier);
	}

	/**
	 * Importe une clé de signature existante au format PEM.
	 * Valide le format de l'identifier (slug) et la présence de la clé privée.
	 *
	 * @throws Error si l'identifier est invalide ou la clé privée manquante
	 */
	async importKey(
		name: string,
		identifier: string,
		privatePem: string,
		certificatePem?: string,
	) {
		if (!/^[a-z0-9-]+$/.test(identifier)) {
			throw new Error(
				"L'identifier ne peut contenir que des lettres minuscules, des chiffres et des tirets",
			);
		}
		if (!privatePem || !privatePem.trim()) {
			throw new Error('La clé privée PEM est requise');
		}
		return this.keysService.importKey(
			name,
			identifier,
			privatePem,
			certificatePem,
		);
	}

	/**
	 * Supprime une clé de signature et toutes ses dépendances.
	 */
	async deleteKey(id: string) {
		return this.keysService.deleteKey(id);
	}

	/**
	 * Crée une nouvelle clé d'API pour une clé de signature.
	 * Retourne la valeur en clair pour affichage unique.
	 */
	async createApiKey(signingKeyId: string, label: string) {
		return this.apiKeyService.createApiKey(signingKeyId, label);
	}

	/**
	 * Révoque une clé d'API.
	 */
	async revokeApiKey(id: string) {
		return this.apiKeyService.revokeApiKey(id);
	}

	/**
	 * Génère un token JWT admin après validation des credentials.
	 */
	async login(username: string, password: string): Promise<string | null> {
		const user = await this.adminAuth.validateAdmin(username, password);
		if (!user) return null;
		return this.adminAuth.generateToken(user);
	}
}
