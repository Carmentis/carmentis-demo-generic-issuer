import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from '../config/config.service';
import { AdminAuthService } from './admin-auth.service';
import { ApiKeyService } from './api-key.service';
import { AdminUserEntity } from './entities/admin-user.entity';
import { ApiKeyEntity } from './entities/api-key.entity';
import { ApiKeyGuard } from './guards/api-key.guard';
import { JwtAdminGuard } from './guards/jwt-admin.guard';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

/**
 * Module d'authentification.
 *
 * Expose :
 * - AdminAuthService : validation credentials + génération JWT
 * - ApiKeyService : création, validation, révocation des clés d'API
 * - JwtAdminGuard : protection des routes admin
 * - ApiKeyGuard : protection des endpoints /api/:name/issue
 */
@Module({
	imports: [
		TypeOrmModule.forFeature([AdminUserEntity, ApiKeyEntity]),
		PassportModule,
		JwtModule.registerAsync({
			inject: [ConfigService],
			useFactory: (config: ConfigService) => ({
				secret: config.jwtSecret,
				signOptions: {
					expiresIn: '8h', // Session admin valide 8 heures
				},
			}),
		}),
	],
	providers: [
		AdminAuthService,
		ApiKeyService,
		LocalStrategy,
		JwtStrategy,
		JwtAdminGuard,
		ApiKeyGuard,
	],
	exports: [AdminAuthService, ApiKeyService, JwtAdminGuard, ApiKeyGuard],
})
export class AuthModule {}
