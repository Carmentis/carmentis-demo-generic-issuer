import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import { engine } from 'express-handlebars';
import helmet from 'helmet';
import * as path from 'path';
import { AppModule } from './app.module';
import { ConfigService } from './config/config.service';
import { IssuerApiModule } from './issuer-api/issuer-api.module';

async function bootstrap() {
	const app = await NestFactory.create<NestExpressApplication>(AppModule);

	// ─────────────────────────────────────────────
	// Sécurité HTTP (en-têtes)
	// ─────────────────────────────────────────────
	app.use(
		helmet({
			// CSP permissive pour Bootstrap CDN
			contentSecurityPolicy: {
				directives: {
					defaultSrc: ["'self'"],
					scriptSrc: [
						"'self'",
						'cdn.jsdelivr.net',
						"'unsafe-inline'",
					],
					styleSrc: ["'self'", 'cdn.jsdelivr.net', "'unsafe-inline'"],
				},
			},
		}),
	);

	// ─────────────────────────────────────────────
	// Middleware de parsing
	// ─────────────────────────────────────────────
	// Cookie parser (requis pour lire le JWT de session admin)
	app.use(cookieParser());

	// Parsing des formulaires HTML (application/x-www-form-urlencoded)
	app.useBodyParser('urlencoded', { extended: true });

	// ─────────────────────────────────────────────
	// Validation globale des DTOs
	// ─────────────────────────────────────────────
	app.useGlobalPipes(
		new ValidationPipe({
			whitelist: true, // Rejette les propriétés non déclarées dans les DTOs
			transform: true, // Convertit les types automatiquement
			forbidNonWhitelisted: false,
		}),
	);

	// ─────────────────────────────────────────────
	// Moteur de templates Handlebars (avec layouts)
	// ─────────────────────────────────────────────
	const viewsDir = path.join(process.cwd(), 'views');
	app.engine(
		'hbs',
		engine({
			extname: '.hbs',
			defaultLayout: 'main',
			layoutsDir: path.join(viewsDir, 'layouts'),
		}),
	);
	app.setBaseViewsDir(viewsDir);
	app.enableCors();
	app.setViewEngine('hbs');

	// ─────────────────────────────────────────────
	// Swagger / OpenAPI
	// ─────────────────────────────────────────────
	const swaggerConfig = new DocumentBuilder()
		.setTitle('SD-JWT Issuer API')
		.setDescription(
			'API générique d\'émission et de vérification de credentials SD-JWT-VC (IETF draft).\n\n' +
			'Les endpoints d\'émission sont protégés par une clé d\'API générée depuis l\'interface d\'administration.',
		)
		.setVersion('1.0')
		.addTag('Credentials', 'Émission, vérification et clé publique')
		.addTag('Status List', 'Liste de révocation IETF Token Status List')
		.addApiKey({ type: 'apiKey', in: 'header', name: 'X-API-Key' }, 'X-API-Key')
		.addBearerAuth({ type: 'http', scheme: 'bearer' }, 'Bearer')
		.build();

	const swaggerDoc = SwaggerModule.createDocument(app, swaggerConfig, {
		include: [IssuerApiModule],
	});
	// UI : /docs   — JSON : /docs-json   — YAML : /docs-yaml
	SwaggerModule.setup('docs', app, swaggerDoc, {
		jsonDocumentUrl: 'docs/openapi.json',
		yamlDocumentUrl: 'docs/openapi.yaml',
	});

	// ─────────────────────────────────────────────
	// Démarrage
	// ─────────────────────────────────────────────
	const config = app.get(ConfigService);
	await app.listen(config.port);

	console.log(`🚀 SD-JWT Issuer démarré sur http://localhost:${config.port}`);
	console.log(`   Admin UI : http://localhost:${config.port}/admin`);
	console.log(
		`   API base : http://localhost:${config.port}/api/<identifier>/...`,
	);
}

bootstrap();
