import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { KeysModule } from '../keys/keys.module';
import { CredentialStatusEntity } from './entities/credential-status.entity';
import { StatusListService } from './status-list.service';

/**
 * Module de gestion de la liste de statut des credentials.
 * Expose StatusListService pour l'émission et la vérification.
 */
@Module({
	imports: [TypeOrmModule.forFeature([CredentialStatusEntity]), KeysModule],
	providers: [StatusListService],
	exports: [StatusListService],
})
export class StatusListModule {}
