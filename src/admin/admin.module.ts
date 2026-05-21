import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { KeysModule } from '../keys/keys.module';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';

/**
 * Module de l'interface d'administration.
 * Gère les routes /admin/* et sert les vues Handlebars.
 */
@Module({
	imports: [KeysModule, AuthModule],
	controllers: [AdminController],
	providers: [AdminService],
})
export class AdminModule {}
