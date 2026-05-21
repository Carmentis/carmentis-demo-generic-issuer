import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class VerifyCredentialDto {
	@ApiProperty({
		description:
			'Token SD-JWT-VC à vérifier. ' +
			'Format compact : `<issuer-signed-jwt>~[<disclosure>~]...~`',
		example: 'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJ...~WyJzYWx0IiwiZ2l2ZW5OYW1lIiwiQWxpY2UiXQ~',
	})
	@IsString()
	token: string;
}
