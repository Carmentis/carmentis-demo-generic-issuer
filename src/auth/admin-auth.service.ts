import {
	Injectable,
	Logger,
	OnModuleInit,
	UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as fs from 'fs';
import { Repository } from 'typeorm';
import { ConfigService } from '../config/config.service';
import { AdminUserEntity } from './entities/admin-user.entity';

/**
 * Service d'authentification admin.
 *
 * Responsabilités :
 * - Création de l'utilisateur admin initial au démarrage (depuis admin_pass.txt)
 * - Validation des credentials (username + password)
 * - Génération des tokens JWT de session admin
 */
@Injectable()
export class AdminAuthService implements OnModuleInit {
	private readonly logger = new Logger(AdminAuthService.name);

	constructor(
		@InjectRepository(AdminUserEntity)
		private readonly adminRepo: Repository<AdminUserEntity>,
		private readonly jwtService: JwtService,
		private readonly config: ConfigService,
	) {}

	/**
	 * Au démarrage : crée l'utilisateur admin si aucun n'existe en base.
	 * Le mot de passe initial est lu depuis admin_pass.txt dans STORAGE_DIR.
	 */
	async onModuleInit(): Promise<void> {
		const count = await this.adminRepo.count();
		if (count > 0) {
			this.logger.log('Utilisateur admin déjà présent en base');
			return;
		}

		const passFile = this.config.adminPassFilePath;
		let password: string;

		if (fs.existsSync(passFile)) {
			password = fs.readFileSync(passFile, 'utf8').trim();
			if (!password) {
				this.logger.error(`Le fichier ${passFile} est vide.`);
				return;
			}
		} else {
			// Générer un mot de passe aléatoire et l'écrire dans le fichier
			password = crypto.randomBytes(16).toString('hex');
			fs.writeFileSync(passFile, password, { encoding: 'utf8', mode: 0o600 });
			this.logger.warn(
				`Aucun fichier ${passFile} trouvé. ` +
					`Mot de passe admin généré automatiquement : ${password}`,
			);
			this.logger.warn(
				`Changez ce mot de passe dès que possible depuis /admin/account`,
			);
		}

		const passwordHash = await bcrypt.hash(password, 12);
		const admin = this.adminRepo.create({
			username: 'admin',
			passwordHash,
		});
		await this.adminRepo.save(admin);
		this.logger.log(
			`Utilisateur admin créé depuis ${passFile}. ` +
				`Vous pouvez supprimer ce fichier après connexion.`,
		);
	}

	/**
	 * Valide les credentials admin (utilisé par LocalStrategy de Passport).
	 *
	 * @returns L'entité AdminUser si valide, null sinon
	 */
	async validateAdmin(
		username: string,
		password: string,
	): Promise<AdminUserEntity | null> {
		const user = await this.adminRepo.findOne({ where: { username } });
		if (!user) return null;

		const valid = await bcrypt.compare(password, user.passwordHash);
		return valid ? user : null;
	}

	/**
	 * Génère un token JWT de session pour l'admin.
	 *
	 * @param user - Entité admin authentifiée
	 * @returns Token JWT signé
	 */
	generateToken(user: AdminUserEntity): string {
		const payload = { sub: user.id, username: user.username };
		return this.jwtService.sign(payload);
	}

	/**
	 * Change le mot de passe d'un utilisateur admin.
	 *
	 * @throws UnauthorizedException si l'ancien mot de passe est incorrect
	 */
	async changePassword(
		userId: string,
		oldPassword: string,
		newPassword: string,
	): Promise<void> {
		const user = await this.adminRepo.findOne({ where: { id: userId } });
		if (!user) throw new UnauthorizedException();

		const valid = await bcrypt.compare(oldPassword, user.passwordHash);
		if (!valid)
			throw new UnauthorizedException('Ancien mot de passe incorrect');

		user.passwordHash = await bcrypt.hash(newPassword, 12);
		await this.adminRepo.save(user);
	}
}
