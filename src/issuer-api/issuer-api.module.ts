import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { KeysModule } from '../keys/keys.module';
import { StatusListModule } from '../status-list/status-list.module';
import { IssuerApiController } from './issuer-api.controller';
import { IssuerApiService } from './issuer-api.service';

/**
 * Module des endpoints publics d'émission et de vérification SD-JWT-VC.
 *
 * Expose les routes /api/:name/* :
 * - publicKey
 * - issue (protégé par API key)
 * - verify
 * - credential/status
 */
@Module({
	imports: [KeysModule, AuthModule, StatusListModule],
	controllers: [IssuerApiController],
	providers: [IssuerApiService],
})
export class IssuerApiModule {}
