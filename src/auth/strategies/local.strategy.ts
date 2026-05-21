import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AdminAuthService } from '../admin-auth.service';
import { AdminUserEntity } from '../entities/admin-user.entity';

/**
 * Stratégie Passport Local pour l'authentification admin par username/password.
 * Utilisée sur la route POST /admin/login.
 */
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
	constructor(private readonly adminAuth: AdminAuthService) {
		super(); // usernameField = 'username', passwordField = 'password' (défaut)
	}

	async validate(
		username: string,
		password: string,
	): Promise<AdminUserEntity> {
		const user = await this.adminAuth.validateAdmin(username, password);
		if (!user) {
			throw new UnauthorizedException('Identifiants invalides');
		}
		return user;
	}
}
