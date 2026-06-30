import {
	Body,
	Controller,
	Get,
	Param,
	Post,
	Redirect,
	Render,
	Req,
	Res,
	UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request, Response } from 'express';
import { AdminAuthService } from '../auth/admin-auth.service';
import { JwtAdminGuard } from '../auth/guards/jwt-admin.guard';
import { AdminService } from './admin.service';

/**
 * Contrôleur de l'interface d'administration.
 * Toutes les routes /admin/* sauf /admin/login sont protégées par JwtAdminGuard.
 *
 * Le JWT admin est stocké dans un cookie httpOnly "access_token".
 */
@Controller('admin')
export class AdminController {
	constructor(
		private readonly adminService: AdminService,
		private readonly adminAuth: AdminAuthService,
	) {}

	// ─────────────────────────────────────────────
	// Authentification
	// ─────────────────────────────────────────────

	/** Affiche le formulaire de connexion */
	@Get('login')
	@Render('admin/login')
	getLoginPage() {
		return { title: 'Connexion', layout: false };
	}

	/**
	 * Traite la soumission du formulaire de connexion.
	 * Utilise la stratégie Passport Local pour valider les credentials.
	 * En cas de succès, émet un JWT dans un cookie httpOnly.
	 */
	@Post('login')
	@UseGuards(AuthGuard('local'))
	async postLogin(@Req() req: Request, @Res() res: Response) {
		// req.user est l'AdminUserEntity validée par LocalStrategy
		const token = this.adminAuth.generateToken(req.user as any);

		// Stocker le JWT dans un cookie httpOnly, SameSite=Strict
		res.cookie('access_token', token, {
			httpOnly: true,
			sameSite: 'strict',
			maxAge: 8 * 60 * 60 * 1000, // 8 heures
		});

		res.redirect('/admin/keys');
	}

	/** Déconnexion : supprime le cookie et redirige vers le login */
	@Post('logout')
	async logout(@Res() res: Response) {
		res.clearCookie('access_token');
		res.redirect('/admin/login');
	}

	/** Redirection de /admin vers /admin/keys */
	@Get()
	@UseGuards(JwtAdminGuard)
	@Redirect('/admin/keys')
	getRoot() {
		return {};
	}

	// ─────────────────────────────────────────────
	// Gestion des clés de signature
	// ─────────────────────────────────────────────

	/** Liste toutes les clés de signature */
	@Get('keys')
	@UseGuards(JwtAdminGuard)
	@Render('admin/keys/list')
	async listKeys() {
		const keys = await this.adminService.getKeysWithStats();
		return { title: 'Clés de signature', keys };
	}

	/** Formulaire de création d'une nouvelle clé */
	@Get('keys/new')
	@UseGuards(JwtAdminGuard)
	@Render('admin/keys/create')
	getCreateKeyPage() {
		return { title: 'Nouvelle clé' };
	}

	/** Traite la création d'une nouvelle clé */
	@Post('keys')
	@UseGuards(JwtAdminGuard)
	async createKey(
		@Body() body: { name: string; identifier: string },
		@Res() res: Response,
	) {
		try {
			await this.adminService.createKey(body.name, body.identifier);
			res.redirect('/admin/keys');
		} catch (error) {
			// En cas d'erreur (identifier invalide ou dupliqué), ré-afficher le formulaire
			res.render('admin/keys/create', {
				title: 'Nouvelle clé',
				error:
					error instanceof Error ? error.message : 'Erreur inconnue',
				form: body,
			});
		}
	}

	/** Formulaire d'import d'une clé existante (PEM) */
	@Get('keys/import')
	@UseGuards(JwtAdminGuard)
	@Render('admin/keys/import')
	getImportKeyPage() {
		return { title: 'Importer une clé' };
	}

	/** Traite l'import d'une clé existante au format PEM */
	@Post('keys/import')
	@UseGuards(JwtAdminGuard)
	async importKey(
		@Body()
		body: {
			name: string;
			identifier: string;
			privateKeyPem: string;
			certificatePem?: string;
		},
		@Res() res: Response,
	) {
		try {
			await this.adminService.importKey(
				body.name,
				body.identifier,
				body.privateKeyPem,
				body.certificatePem,
			);
			res.redirect('/admin/keys');
		} catch (error) {
			res.render('admin/keys/import', {
				title: 'Importer une clé',
				error:
					error instanceof Error ? error.message : 'Erreur inconnue',
				form: body,
			});
		}
	}

	/** Affiche le détail d'une clé avec ses clés d'API */
	@Get('keys/:id')
	@UseGuards(JwtAdminGuard)
	@Render('admin/keys/detail')
	async getKeyDetail(@Param('id') id: string) {
		const key = await this.adminService.getKeyDetail(id);
		return { title: `Clé : ${key.name}`, key };
	}

	/** Supprime une clé de signature */
	@Post('keys/:id/delete')
	@UseGuards(JwtAdminGuard)
	async deleteKey(@Param('id') id: string, @Res() res: Response) {
		await this.adminService.deleteKey(id);
		res.redirect('/admin/keys');
	}

	// ─────────────────────────────────────────────
	// Gestion des clés d'API
	// ─────────────────────────────────────────────

	/** Formulaire de création d'une clé d'API pour une clé de signature */
	@Get('keys/:keyId/api-keys/new')
	@UseGuards(JwtAdminGuard)
	@Render('admin/api-keys/create')
	async getCreateApiKeyPage(@Param('keyId') keyId: string) {
		const key = await this.adminService.getKeyDetail(keyId);
		return { title: "Nouvelle clé d'API", key };
	}

	/**
	 * Crée une nouvelle clé d'API.
	 * Redirige vers une page de confirmation qui affiche la clé en clair UNE SEULE FOIS.
	 */
	@Post('keys/:keyId/api-keys')
	@UseGuards(JwtAdminGuard)
	async createApiKey(
		@Param('keyId') keyId: string,
		@Body() body: { label: string },
		@Res() res: Response,
	) {
		const { entity, plainKey } = await this.adminService.createApiKey(
			keyId,
			body.label,
		);
		// Afficher la clé en clair une seule fois (ne pas rediriger)
		res.render('admin/api-keys/created', {
			title: "Clé d'API créée",
			apiKey: entity,
			plainKey,
			keyId,
		});
	}

	/** Révoque une clé d'API */
	@Post('keys/:keyId/api-keys/:id/revoke')
	@UseGuards(JwtAdminGuard)
	async revokeApiKey(
		@Param('keyId') keyId: string,
		@Param('id') id: string,
		@Res() res: Response,
	) {
		await this.adminService.revokeApiKey(id);
		res.redirect(`/admin/keys/${keyId}`);
	}

	// ─────────────────────────────────────────────
	// Compte admin (changement de mot de passe)
	// ─────────────────────────────────────────────

	/** Formulaire de changement de mot de passe */
	@Get('account')
	@UseGuards(JwtAdminGuard)
	@Render('admin/account')
	getAccountPage() {
		return { title: 'Mon compte' };
	}

	/** Traite le changement de mot de passe */
	@Post('account/change-password')
	@UseGuards(JwtAdminGuard)
	async changePassword(
		@Req() req: Request,
		@Body() body: { oldPassword: string; newPassword: string; confirmPassword: string },
		@Res() res: Response,
	) {
		if (body.newPassword !== body.confirmPassword) {
			return res.render('admin/account', {
				title: 'Mon compte',
				error: 'Les nouveaux mots de passe ne correspondent pas.',
			});
		}
		try {
			const user = (req as any).user as { id: string };
			await this.adminAuth.changePassword(user.id, body.oldPassword, body.newPassword);
			res.render('admin/account', {
				title: 'Mon compte',
				success: 'Mot de passe modifié avec succès.',
			});
		} catch (error) {
			res.render('admin/account', {
				title: 'Mon compte',
				error: error instanceof Error ? error.message : 'Erreur inconnue',
			});
		}
	}
}
