import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { KeysService } from './keys.service';
import { SigningKeyEntity } from './entities/signing-key.entity';

/**
 * Module de gestion des clés de signature Ed25519.
 * Expose KeysService aux autres modules.
 */
@Module({
	imports: [TypeOrmModule.forFeature([SigningKeyEntity])],
	providers: [KeysService],
	exports: [KeysService],
})
export class KeysModule {}
