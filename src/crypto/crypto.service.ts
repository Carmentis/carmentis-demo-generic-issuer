import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import * as jose from 'jose';
import { base64url } from 'jose';
import { ConfigService } from '../config/config.service';

/**
 * Résultat du chiffrement AES-256-GCM d'une clé privée.
 */
export interface EncryptedKey {
	/** Texte chiffré encodé en base64 */
	ciphertext: string;
	/** Vecteur d'initialisation (12 octets) encodé en base64 */
	iv: string;
	/** Étiquette d'authentification GCM (16 octets) encodée en base64 */
	tag: string;
}

/**
 * Service utilitaire de cryptographie.
 *
 * Fournit :
 * - Génération de paires de clés Ed25519 (JWK)
 * - Chiffrement / déchiffrement AES-256-GCM des clés privées pour la BDD
 * - Signature / vérification Ed25519 (utilisées par SDJwtInstance)
 * - Fonctions utilitaires : hash, sel, challenge, token UUID
 *
 * Ce service n'héberge aucune clé propre : les clés sont gérées par KeysService.
 */
@Injectable()
export class CryptoService {
	private readonly logger = new Logger(CryptoService.name);

	/**
	 * Clé AES-256 dérivée de STORAGE_SECRET via HKDF.
	 * Calculée une seule fois à l'injection (déterministe).
	 */
	private readonly aesKey: Buffer;

	constructor(private readonly config: ConfigService) {
		// HKDF : même STORAGE_SECRET → même clé AES (pas besoin de stocker le sel)
		this.aesKey = Buffer.from(
			crypto.hkdfSync(
				'sha256',
				Buffer.from(config.storageSecret, 'utf8'),
				Buffer.from('carmentis-issuer', 'utf8'), // sel statique applicatif
				Buffer.from('key-encryption', 'utf8'), // contexte de dérivation
				32, // 256 bits
			),
		);
	}

	// ─────────────────────────────────────────────
	// Génération de clés Ed25519
	// ─────────────────────────────────────────────

	/**
	 * Génère une nouvelle paire de clés Ed25519 et retourne les deux JWK.
	 */
	async generateEd25519KeyPair(): Promise<{
		publicJwk: Record<string, string>;
		privateJwk: Record<string, string>;
	}> {
		const { publicKey, privateKey } = await jose.generateKeyPair('EdDSA', {
			crv: 'Ed25519',
			extractable: true,
		});
		const publicJwk = (await jose.exportJWK(publicKey)) as Record<
			string,
			string
		>;
		const privateJwk = (await jose.exportJWK(privateKey)) as Record<
			string,
			string
		>;
		return { publicJwk, privateJwk };
	}

	/**
	 * Construit la représentation did:jwk d'une clé publique JWK.
	 * Format : did:jwk:<base64url(JSON(publicJwk))>
	 */
	buildDidJwk(publicJwk: Record<string, unknown>): string {
		return `did:jwk:${base64url.encode(JSON.stringify(publicJwk))}`;
	}

	// ─────────────────────────────────────────────
	// Détermination de l'algorithme JWS depuis un JWK
	// ─────────────────────────────────────────────

	/**
	 * Déduit l'algorithme de signature JOSE (alg) et les paramètres node:crypto
	 * correspondants à partir du type/courbe d'un JWK.
	 *
	 * Supporte : Ed25519/Ed448 (EdDSA), EC P-256/384/521 et secp256k1 (ES*), RSA (RS256).
	 *
	 * @throws Error si le type de clé n'est pas supporté
	 */
	private algParams(jwk: Record<string, unknown>): {
		alg: string;
		/** Algorithme de hachage node ; null pour EdDSA (signature directe). */
		digest: string | null;
		/** Encodage DSA pour ECDSA (raw r||s attendu par JOSE). */
		dsaEncoding?: crypto.DSAEncoding;
	} {
		const kty = jwk.kty as string;
		if (kty === 'OKP') {
			// Ed25519 / Ed448 : signature directe sans pré-hachage
			return { alg: 'EdDSA', digest: null };
		}
		if (kty === 'EC') {
			const crv = jwk.crv as string;
			const map: Record<string, { alg: string; digest: string }> = {
				'P-256': { alg: 'ES256', digest: 'sha256' },
				'P-384': { alg: 'ES384', digest: 'sha384' },
				'P-521': { alg: 'ES512', digest: 'sha512' },
				secp256k1: { alg: 'ES256K', digest: 'sha256' },
			};
			const entry = map[crv];
			if (!entry) {
				throw new Error(`Courbe EC non supportée : ${crv}`);
			}
			// ieee-p1363 → signature brute concaténée (r||s) conforme JOSE
			return { ...entry, dsaEncoding: 'ieee-p1363' };
		}
		if (kty === 'RSA') {
			return { alg: 'RS256', digest: 'sha256' };
		}
		throw new Error(`Type de clé non supporté : ${kty}`);
	}

	/**
	 * Retourne l'algorithme de signature JOSE (ex: "EdDSA", "ES256", "RS256")
	 * correspondant à un JWK (public ou privé).
	 */
	algForJwk(jwk: Record<string, unknown>): string {
		return this.algParams(jwk).alg;
	}

	// ─────────────────────────────────────────────
	// Import de clés / certificats PEM
	// ─────────────────────────────────────────────

	/**
	 * Importe une clé privée PEM (PKCS#8 ou SEC1) et en dérive les JWK
	 * public et privé. La clé publique est dérivée de la clé privée afin
	 * de garantir la cohérence de la paire, quel que soit le type/courbe.
	 *
	 * @throws Error si le PEM est invalide ou le type de clé non supporté
	 */
	importKeyPairFromPem(privatePem: string): {
		publicJwk: Record<string, unknown>;
		privateJwk: Record<string, unknown>;
	} {
		const privateKey = crypto.createPrivateKey(privatePem);
		const privateJwk = privateKey.export({ format: 'jwk' }) as Record<
			string,
			unknown
		>;
		const publicJwk = crypto
			.createPublicKey(privateKey)
			.export({ format: 'jwk' }) as Record<string, unknown>;

		// Valide que le type est supporté (lève sinon)
		this.algParams(publicJwk);

		return { publicJwk, privateJwk };
	}

	/**
	 * Extrait la chaîne de certificats d'un PEM en valeurs base64 DER,
	 * telles qu'attendues dans le champ JWK `x5c` (base64 standard, non url).
	 * Supporte plusieurs certificats concaténés (chaîne).
	 *
	 * @throws Error si aucun certificat valide n'est trouvé
	 */
	parseCertificateChainPem(certPem: string): string[] {
		const blocks = certPem.match(
			/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g,
		);
		if (!blocks || blocks.length === 0) {
			throw new Error('Aucun certificat PEM valide trouvé');
		}
		return blocks.map((block) => {
			const base64 = block
				.replace(/-----BEGIN CERTIFICATE-----/, '')
				.replace(/-----END CERTIFICATE-----/, '')
				.replace(/\s+/g, '');
			// Valide que le contenu est bien un certificat X.509 décodable
			new crypto.X509Certificate(block);
			return base64;
		});
	}

	// ─────────────────────────────────────────────
	// Chiffrement / déchiffrement AES-256-GCM
	// ─────────────────────────────────────────────

	/**
	 * Chiffre le JSON d'une clé privée JWK avec AES-256-GCM.
	 * IV aléatoire de 12 octets généré à chaque appel.
	 *
	 * @param privateJwkJson - JSON stringifié du JWK privé
	 * @returns { ciphertext, iv, tag } tous en base64
	 */
	encryptPrivateKey(privateJwkJson: string): EncryptedKey {
		const iv = crypto.randomBytes(12);
		const cipher = crypto.createCipheriv('aes-256-gcm', this.aesKey, iv);

		const ciphertextBuf = Buffer.concat([
			cipher.update(privateJwkJson, 'utf8'),
			cipher.final(),
		]);
		const tag = cipher.getAuthTag(); // 16 octets

		return {
			ciphertext: ciphertextBuf.toString('base64'),
			iv: iv.toString('base64'),
			tag: tag.toString('base64'),
		};
	}

	/**
	 * Déchiffre une clé privée stockée en base (AES-256-GCM).
	 * Lève une erreur si le tag d'authentification GCM est invalide.
	 *
	 * @returns JSON stringifié du JWK privé
	 */
	decryptPrivateKey(encrypted: EncryptedKey): string {
		const iv = Buffer.from(encrypted.iv, 'base64');
		const tag = Buffer.from(encrypted.tag, 'base64');
		const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');

		const decipher = crypto.createDecipheriv(
			'aes-256-gcm',
			this.aesKey,
			iv,
		);
		decipher.setAuthTag(tag);

		return Buffer.concat([
			decipher.update(ciphertext),
			decipher.final(),
		]).toString('utf8');
	}

	// ─────────────────────────────────────────────
	// Signature / vérification Ed25519 (bas niveau)
	// Utilisées comme callbacks dans SDJwtInstance
	// ─────────────────────────────────────────────

	/**
	 * Signe des données avec une clé privée JWK Ed25519.
	 *
	 * @param data - Données à signer
	 * @param privateJwk - JWK privé Ed25519
	 * @returns Signature encodée en base64url
	 */
	async signWithKey(
		data: string,
		privateJwk: Record<string, unknown>,
	): Promise<string> {
		const { digest, dsaEncoding } = this.algParams(privateJwk);
		const sig = crypto.sign(digest, Buffer.from(data), {
			format: 'jwk',
			key: privateJwk as crypto.JsonWebKey,
			...(dsaEncoding ? { dsaEncoding } : {}),
		});
		return Buffer.from(sig).toString('base64url');
	}

	/**
	 * Vérifie une signature avec une clé publique JWK, en sélectionnant
	 * automatiquement l'algorithme adapté au type de clé.
	 */
	verifyWithKey(
		data: string,
		signature: string,
		publicJwk: Record<string, unknown>,
	): boolean {
		const { digest, dsaEncoding } = this.algParams(publicJwk);
		return crypto.verify(
			digest,
			Buffer.from(data),
			{
				format: 'jwk',
				key: publicJwk as crypto.JsonWebKey,
				...(dsaEncoding ? { dsaEncoding } : {}),
			},
			Buffer.from(signature, 'base64url'),
		);
	}

	/**
	 * Vérifie une signature Ed25519 à partir d'un did:jwk.
	 * Extrait la clé publique encodée dans le DID.
	 */
	verifyWithDidJwk(data: string, signature: string, didJwk: string): boolean {
		const parts = didJwk.split(':');
		if (parts.length < 3 || parts[0] !== 'did' || parts[1] !== 'jwk') {
			return false;
		}
		const publicJwk = JSON.parse(
			Buffer.from(parts[2], 'base64url').toString('utf8'),
		) as Record<string, string>;
		return this.verifyWithKey(data, signature, publicJwk);
	}

	// ─────────────────────────────────────────────
	// Utilitaires généraux
	// ─────────────────────────────────────────────

	/**
	 * Calcule le hash d'une chaîne.
	 * Utilisé par SDJwtInstance (ex: algorithm = "sha-256").
	 */
	async hash(data: string, algorithm: string): Promise<Uint8Array> {
		const normalized = algorithm.replace('-', '').toLowerCase();
		return new Uint8Array(
			crypto.createHash(normalized).update(data).digest(),
		);
	}

	/** Génère un sel aléatoire en base64url (16 octets). */
	async generateSalt(): Promise<string> {
		return crypto.randomBytes(16).toString('base64url');
	}

	/** Génère un challenge aléatoire en base64url (32 octets). */
	generateChallenge(): string {
		return crypto.randomBytes(32).toString('base64url');
	}

	/** Génère un UUID v4 aléatoire. */
	generateToken(): string {
		return crypto.randomUUID();
	}
}
