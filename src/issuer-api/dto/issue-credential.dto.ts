import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
	IsArray,
	IsNumber,
	IsObject,
	IsOptional,
	IsString,
	Matches,
	Min,
} from 'class-validator';

/**
 * DTO pour l'émission d'un SD-JWT-VC.
 *
 * Exemple de requête :
 * ```json
 * {
 *   "vct": "UniversityDegreeCredential",
 *   "subject": "did:jwk:...",
 *   "claims": {
 *     "givenName": "Alice",
 *     "familyName": "Dupont",
 *     "degree": "Master Informatique"
 *   },
 *   "disclosableClaims": ["givenName", "familyName"],
 *   "exp": 1893456000
 * }
 * ```
 */
export class IssueCredentialDto {
	@ApiProperty({
		description: 'Type du Verifiable Credential (claim `vct` du SD-JWT-VC).',
		example: 'UniversityDegreeCredential',
	})
	@IsString()
	vct: string;

	@ApiPropertyOptional({
		description: 'Sujet du credential (claim `sub`). Généralement un DID ou identifiant du titulaire.',
		example: 'did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ii4uLiJ9',
	})
	@IsOptional()
	@IsString()
	subject?: string;

	@ApiProperty({
		description:
			'Claims personnalisés inclus à plat dans le payload. ' +
			'Les claims réservés (`iss`, `iat`, `exp`, `vct`, `sub`, `jti`, `status`) sont gérés automatiquement.',
		example: { givenName: 'Alice', familyName: 'Dupont', degree: 'Master Informatique' },
	})
	@IsObject()
	claims: Record<string, unknown>;

	@ApiProperty({
		description:
			'Noms des claims qui seront divulgables sélectivement (SD-JWT disclosures). ' +
			'Les claims absents de cette liste sont inclus en clair dans le JWT.',
		example: ['givenName', 'familyName'],
		type: [String],
	})
	@IsArray()
	@IsString({ each: true })
	disclosableClaims: string[];

	@ApiPropertyOptional({
		description: 'Timestamp d\'expiration Unix. Si absent, le credential n\'expire pas.',
		example: 1893456000,
	})
	@IsOptional()
	@IsNumber()
	@Min(0)
	exp?: number;
}
