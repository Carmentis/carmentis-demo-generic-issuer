import { Global, Module } from '@nestjs/common';
import { ConfigService } from './config.service';

/**
 * Module global de configuration.
 * Expose ConfigService à tous les autres modules sans import explicite.
 */
@Global()
@Module({
	providers: [ConfigService],
	exports: [ConfigService],
})
export class AppConfigModule {}
