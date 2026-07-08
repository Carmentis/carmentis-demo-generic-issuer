import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { parse } from 'smol-toml';

/**
 * Service de configuration global.
 *
 * Priorité de résolution pour chaque valeur (de la plus forte à la plus faible) :
 *   1. Variable d'environnement (si définie et non vide)
 *   2. Valeur dans config.toml
 *   3. Valeur par défaut codée en dur (port uniquement)
 *
 * Le fichier TOML est cherché dans l'ordre :
 *   1. Chemin fourni par la variable d'env CONFIG_FILE
 *   2. ./config.toml à la racine du projet (CWD)
 *
 * Si aucun fichier n'est trouvé, la configuration retombe entièrement
 * sur les variables d'environnement (comportement rétrocompatible).
 *
 * Structure attendue du config.toml :
 * ```toml
 * [server]
 * port = 3000
 *
 * [storage]
 * dir    = "/data/issuer"
 * secret = "secret-de-32-caractères-minimum"
 *
 * [auth]
 * jwt_secret = "secret-jwt"
 * ```
 */
@Injectable()
export class ConfigService implements OnModuleInit {
	private readonly logger = new Logger(ConfigService.name);

	/** Contenu parsé du fichier config.toml (vide si absent) */
	private readonly toml: Record<string, unknown> = {};

	constructor() {
		// Charger le TOML dans le constructeur (synchrone) pour que les getters
		// soient utilisables dès l'injection, avant onModuleInit.
		const configFile =
			process.env.CONFIG_FILE ?? path.join(process.cwd(), 'config.toml');

		if (fs.existsSync(configFile)) {
			try {
				const raw = fs.readFileSync(configFile, 'utf8');
				this.toml = parse(raw) as Record<string, unknown>;
				this.logger.log(
					`Configuration TOML chargée depuis : ${configFile}`,
				);
			} catch (err) {
				// Un fichier TOML invalide est une erreur fatale
				throw new Error(
					`Impossible de parser ${configFile} : ${err instanceof Error ? err.message : String(err)}`,
				);
			}
		} else {
			this.logger.debug(
				`Aucun fichier config.toml trouvé (${configFile}), utilisation des variables d'environnement`,
			);
		}
	}

	// ─────────────────────────────────────────────
	// Initialisation et validation
	// ─────────────────────────────────────────────

	onModuleInit(): void {
		// Valider que les clés obligatoires sont présentes (quelle que soit leur source)
		const missing: string[] = [];
		if (!this.resolve('STORAGE_DIR', ['storage', 'dir']))
			missing.push('storage.dir / STORAGE_DIR');
		if (!this.resolve('STORAGE_SECRET', ['storage', 'secret']))
			missing.push('storage.secret / STORAGE_SECRET');
		if (!this.resolve('JWT_SECRET', ['auth', 'jwt_secret']))
			missing.push('auth.jwt_secret / JWT_SECRET');

		if (missing.length > 0) {
			throw new Error(
				`Configuration manquante — définissez ces valeurs dans config.toml ou en variable d'environnement :\n  ${missing.join('\n  ')}`,
			);
		}

		if (this.storageSecret.length < 32) {
			throw new Error(
				'storage.secret / STORAGE_SECRET doit faire au moins 32 caractères',
			);
		}

		// Créer le répertoire de stockage si absent
		const storageDir = this.storageDir;
		if (!fs.existsSync(storageDir)) {
			fs.mkdirSync(storageDir, { recursive: true });
			this.logger.log(`Répertoire de stockage créé : ${storageDir}`);
		}

		this.logger.log(`Répertoire de stockage : ${storageDir}`);
	}

	// ─────────────────────────────────────────────
	// Getters publics (interface inchangée)
	// ─────────────────────────────────────────────

	/** Chemin du répertoire de stockage (SQLite, admin_pass.txt) */
	get storageDir(): string {
		return path.resolve(this.resolve('STORAGE_DIR', ['storage', 'dir'])!);
	}

	/** Secret de dérivation AES pour le chiffrement des clés privées */
	get storageSecret(): string {
		return this.resolve('STORAGE_SECRET', ['storage', 'secret'])!;
	}

	get issuerBaseUrl(): string {
		return this.resolve('ISSUER_BASE_URL', ['server', 'issuer_base_url'])!;
	}

	/** Secret JWT pour les sessions admin */
	get jwtSecret(): string {
		return this.resolve('JWT_SECRET', ['auth', 'jwt_secret'])!;
	}

	/** Port d'écoute du serveur (défaut : 3000) */
	get port(): number {
		return parseInt(this.resolve('PORT', ['server', 'port'], '3000')!, 10);
	}

	/** Chemin complet vers la base de données SQLite */
	get databasePath(): string {
		return path.join(this.storageDir, 'issuer.sqlite');
	}

	/** Chemin complet vers le fichier de mot de passe admin initial */
	get adminPassFilePath(): string {
		return path.join(this.storageDir, 'admin_pass.txt');
	}

	// ─────────────────────────────────────────────
	// Résolution interne : env > TOML > défaut
	// ─────────────────────────────────────────────

	/**
	 * Résout une valeur de configuration selon la priorité :
	 * variable d'environnement > clé TOML > valeur par défaut.
	 *
	 * @param envKey    - Nom de la variable d'environnement
	 * @param tomlPath  - Chemin dans le TOML (ex: ['storage', 'dir'])
	 * @param fallback  - Valeur par défaut si aucune source ne fournit la valeur
	 */
	private resolve(
		envKey: string,
		tomlPath: string[],
		fallback?: string,
	): string | undefined {
		// 1. Variable d'environnement
		const envVal = process.env[envKey];
		if (envVal !== undefined && envVal !== '') {
			this.logger.debug(`${envKey} → depuis variable d'environnement`);
			return envVal;
		}

		// 2. Fichier TOML
		const tomlVal = tomlPath.reduce<unknown>(
			(obj, key) =>
				obj !== null &&
				typeof obj === 'object' &&
				key in (obj as Record<string, unknown>)
					? (obj as Record<string, unknown>)[key]
					: undefined,
			this.toml,
		);
		if (tomlVal !== undefined && tomlVal !== null) {
			this.logger.debug(
				`${envKey} → depuis config.toml [${tomlPath.join('.')}]`,
			);
			return String(tomlVal);
		}

		// 3. Valeur par défaut
		if (fallback !== undefined) {
			this.logger.debug(`${envKey} → valeur par défaut (${fallback})`);
			return fallback;
		}

		return undefined;
	}
}
