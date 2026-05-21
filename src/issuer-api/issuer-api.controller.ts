import {
	Body,
	Controller,
	Get,
	Param,
	Post,
	Query,
	Req,
	Res,
	UseGuards,
} from '@nestjs/common';
import {
	ApiOperation,
	ApiParam,
	ApiQuery,
	ApiResponse,
	ApiSecurity,
	ApiTags,
} from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { KeysService } from '../keys/keys.service';
import { StatusListService } from '../status-list/status-list.service';
import { IssueCredentialDto } from './dto/issue-credential.dto';
import { VerifyCredentialDto } from './dto/verify-credential.dto';
import { IssuerApiService } from './issuer-api.service';

/**
 * Contrôleur des endpoints publics de l'API d'émission et de vérification.
 *
 * Toutes les routes sont préfixées par /api/:name où :name est l'identifier
 * (slug) de la clé de signature.
 *
 * Routes :
 * - GET  /api/:name/publicKey        → clé publique (JWK ou did:jwk)
 * - POST /api/:name/issue            → émettre un SD-JWT-VC [protégé par API key]
 * - GET  /api/:name/verify           → vérifier un SD-JWT-VC (token en query)
 * - POST /api/:name/verify           → vérifier un SD-JWT-VC (token en body)
 * - GET  /api/:name/credential/status → liste de statut (bitstring JWT)
 */
@ApiTags('Credentials')
@ApiParam({ name: 'name', description: 'Identifier (slug) de la clé de signature', example: 'universite-paris' })
@Controller('api/:name')
export class IssuerApiController {
	constructor(
		private readonly keysService: KeysService,
		private readonly issuerService: IssuerApiService,
		private readonly statusListService: StatusListService,
	) {}

	@ApiOperation({ summary: 'Clé publique de l\'émetteur' })
	@ApiQuery({
		name: 'format',
		required: false,
		enum: ['jwk', 'did-jwk'],
		description:
			'`jwk` (défaut) — retourne le JWK brut.\n\n' +
			'`did-jwk` — retourne le DID au format `did:jwk:<base64url(JWK)>`.',
		example: 'did-jwk',
	})
	@ApiResponse({ status: 200, description: 'JWK ou did:jwk selon le paramètre `format`.' })
	@ApiResponse({ status: 404, description: 'Clé de signature introuvable.' })
	@Get('publicKey')
	async getPublicKey(
		@Param('name') name: string,
		@Query('format') format: 'jwk' | 'did-jwk' = 'jwk',
	) {
		const signingKey = await this.keysService.findByIdentifier(name);
		return this.issuerService.getPublicKey(signingKey, format);
	}

	@ApiOperation({ summary: 'Émettre un SD-JWT-VC' })
	@ApiSecurity('X-API-Key')
	@ApiSecurity('Bearer')
	@ApiResponse({ status: 201, description: 'Credential émis. Retourne `{ credential: "<sd-jwt-vc>" }`.' })
	@ApiResponse({ status: 401, description: 'Clé d\'API manquante ou invalide.' })
	@ApiResponse({ status: 404, description: 'Clé de signature introuvable.' })
	@Post('issue')
	@UseGuards(ApiKeyGuard)
	async issueCredential(
		@Param('name') name: string,
		@Body() dto: IssueCredentialDto,
		@Req() req: Request,
	) {
		const signingKey = await this.keysService.findByIdentifier(name);
		const credential = await this.issuerService.issueCredential(
			signingKey,
			dto,
			req,
		);
		return { credential };
	}

	@ApiOperation({ summary: 'Vérifier un SD-JWT-VC (token en query)' })
	@ApiQuery({ name: 'token', description: 'Token SD-JWT-VC compact', required: true })
	@ApiResponse({ status: 200, description: '`{ valid: true, payload: {...} }` ou `{ valid: false, error: "..." }`.' })
	@Get('verify')
	async verifyCredentialGet(
		@Param('name') name: string,
		@Query('token') token: string,
	) {
		const signingKey = await this.keysService.findByIdentifier(name);
		return this.issuerService.verifyCredential(signingKey, token);
	}

	@ApiOperation({ summary: 'Vérifier un SD-JWT-VC (token en body)' })
	@ApiResponse({ status: 200, description: '`{ valid: true, payload: {...} }` ou `{ valid: false, error: "..." }`.' })
	@Post('verify')
	async verifyCredentialPost(
		@Param('name') name: string,
		@Body() dto: VerifyCredentialDto,
	) {
		const signingKey = await this.keysService.findByIdentifier(name);
		return this.issuerService.verifyCredential(signingKey, dto.token);
	}

	@ApiTags('Status List')
	@ApiOperation({ summary: 'Liste de statut de révocation (IETF Token Status List)' })
	@ApiResponse({
		status: 200,
		description: 'JWT signé (Content-Type: `application/statuslist+jwt`) conforme à draft-ietf-oauth-status-list.',
	})
	@Get('credential/status')
	async getCredentialStatus(
		@Param('name') name: string,
		@Res() res: Response,
	) {
		const signingKey = await this.keysService.findByIdentifier(name);
		const jwt = await this.statusListService.buildStatusListJwt(signingKey);

		res.setHeader('Content-Type', 'application/statuslist+jwt');
		res.send(jwt);
	}
}
