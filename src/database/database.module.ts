import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from '../config/config.service';
import { SigningKeyEntity } from '../keys/entities/signing-key.entity';
import { AdminUserEntity } from '../auth/entities/admin-user.entity';
import { ApiKeyEntity } from '../auth/entities/api-key.entity';
import { CredentialStatusEntity } from '../status-list/entities/credential-status.entity';

/**
 * Module de base de données.
 * Configure TypeORM avec SQLite (better-sqlite3) en utilisant le chemin
 * défini par ConfigService. Les entités sont synchronisées automatiquement.
 */
@Module({
	imports: [
		TypeOrmModule.forRootAsync({
			inject: [ConfigService],
			useFactory: (config: ConfigService) => ({
				type: 'better-sqlite3',
				database: config.databasePath,
				// Synchronise le schéma au démarrage (acceptable pour dev/petits projets)
				synchronize: true,
				entities: [
					SigningKeyEntity,
					AdminUserEntity,
					ApiKeyEntity,
					CredentialStatusEntity,
				],
			}),
		}),
	],
})
export class DatabaseModule {}
