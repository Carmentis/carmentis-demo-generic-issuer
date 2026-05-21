import {
	ExecutionContext,
	Injectable,
	UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';

/**
 * Guard JWT pour les routes admin.
 *
 * En cas d'échec d'authentification :
 * - Redirige vers /admin/login pour les requêtes de navigation (Accept: text/html)
 * - Retourne 401 pour les requêtes API (Accept: application/json)
 */
@Injectable()
export class JwtAdminGuard extends AuthGuard('jwt') {
	handleRequest<TUser>(
		err: any,
		user: TUser,
		_info: any,
		context: ExecutionContext,
	): TUser {
		const req = context.switchToHttp().getRequest<Request>();
		const res = context.switchToHttp().getResponse<Response>();

		if (err || !user) {
			const acceptsHtml = req.accepts(['html', 'json']) === 'html';
			if (acceptsHtml) {
				res.redirect('/admin/login');
				// Retourner null pour éviter une exception supplémentaire
				// (la redirection a déjà été envoyée)
				return null as unknown as TUser;
			}
			throw (
				err ??
				new UnauthorizedException('Token admin invalide ou manquant')
			);
		}

		return user;
	}
}
