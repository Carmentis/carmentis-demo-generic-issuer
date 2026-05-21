import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { ConfigService } from '../../config/config.service';

/** Payload décodé du token JWT admin */
export interface JwtPayload {
	sub: string;
	username: string;
}

/**
 * Stratégie Passport JWT pour les routes admin protégées.
 *
 * Lit le token JWT depuis :
 * 1. Le cookie httpOnly "access_token" (navigation web)
 * 2. L'en-tête Authorization: Bearer (appels API)
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(private readonly config: ConfigService) {
		super({
			// Essaye d'abord le cookie, puis le header Authorization
			jwtFromRequest: ExtractJwt.fromExtractors([
				(req: Request) => {
					return req?.cookies?.['access_token'] ?? null;
				},
				ExtractJwt.fromAuthHeaderAsBearerToken(),
			]),
			ignoreExpiration: false,
			secretOrKey: config.jwtSecret,
		});
	}

	validate(payload: JwtPayload): JwtPayload {
		// Le payload est retourné tel quel et attaché à req.user
		return payload;
	}
}
