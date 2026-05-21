import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { AdminModule } from './admin/admin.module';
import { AppConfigModule } from './config/config.module';
import { CryptoModule } from './crypto/crypto.module';
import { DatabaseModule } from './database/database.module';
import { IssuerApiModule } from './issuer-api/issuer-api.module';
import { KeysModule } from './keys/keys.module';
import { StatusListModule } from './status-list/status-list.module';

/**
 * Module racine de l'application.
 *
 * Ordre d'initialisation important :
 * 1. AppConfigModule (global) — valide les env vars et crée STORAGE_DIR
 * 2. DatabaseModule — connecte SQLite, synchronise le schéma
 * 3. CryptoModule (global) — dérive la clé AES depuis STORAGE_SECRET
 * 4. Modules métier — KeysModule, AuthModule (via AdminModule/IssuerApiModule)
 * 5. StatusListModule, IssuerApiModule, AdminModule
 */
@Module({
	imports: [
		// ── Infrastructure ──────────────────────────────────
		AppConfigModule, // @Global — ConfigService disponible partout
		DatabaseModule, // TypeORM + SQLite
		CryptoModule, // @Global — CryptoService disponible partout

		// ── Rate limiting global ─────────────────────────────
		ThrottlerModule.forRoot([
			{
				name: 'default',
				ttl: 60000, // Fenêtre de 60 secondes
				limit: 100, // 100 requêtes max par IP sur les routes publiques
			},
		]),

		// ── Modules métier ───────────────────────────────────
		KeysModule,
		StatusListModule,
		IssuerApiModule,
		AdminModule,
	],
})
export class AppModule {}
