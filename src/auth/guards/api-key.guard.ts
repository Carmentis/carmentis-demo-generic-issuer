import {
	CanActivate,
	ExecutionContext,
	Injectable,
	UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { ApiKeyService } from '../api-key.service';

/**
 * Guard d'authentification par clé d'API pour les endpoints publics protégés.
 *
 * Lit la clé d'API depuis (dans cet ordre) :
 * 1. L'en-tête X-API-Key
 * 2. L'en-tête Authorization: Bearer <api-key>
 *
 * Valide que :
 * - La clé existe en base et n'est pas révoquée
 * - La clé est associée à la clé de signature dont l'identifier correspond au :name de l'URL
 *
 * Si valide, attache l'entité ApiKey à req.apiKey pour les handlers en aval.
 */
@Injectable()
export class ApiKeyGuard implements CanActivate {
	constructor(private readonly apiKeyService: ApiKeyService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const req = context
			.switchToHttp()
			.getRequest<Request & { apiKey?: any }>();

		// Extraire la clé brute depuis les headers
		const rawKey = this.extractKey(req);
		if (!rawKey) {
			throw new UnauthorizedException("Clé d'API manquante");
		}

		// Valider la clé en base
		const apiKey = await this.apiKeyService.validateApiKey(rawKey);
		if (!apiKey) {
			throw new UnauthorizedException("Clé d'API invalide ou révoquée");
		}

		// Vérifier que la clé d'API appartient bien à la clé de signature du :name en URL
		const nameParam = req.params?.name;
		if (nameParam && apiKey.signingKey?.identifier !== nameParam) {
			throw new UnauthorizedException(
				"Cette clé d'API n'est pas autorisée pour cet endpoint",
			);
		}

		// Attacher l'entité pour les handlers
		req.apiKey = apiKey;
		return true;
	}

	/** Extrait la clé brute depuis X-API-Key ou Authorization: Bearer */
	private extractKey(req: Request): string | null {
		// Priorité à X-API-Key
		const xApiKey = req.headers['x-api-key'];
		if (xApiKey) {
			return Array.isArray(xApiKey) ? xApiKey[0] : xApiKey;
		}

		// Fallback sur Authorization: Bearer
		const authHeader = req.headers['authorization'];
		if (authHeader?.startsWith('Bearer ')) {
			return authHeader.slice(7);
		}

		return null;
	}
}
