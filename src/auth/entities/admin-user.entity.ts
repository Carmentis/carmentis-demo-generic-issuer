import {
	Column,
	CreateDateColumn,
	Entity,
	PrimaryGeneratedColumn,
} from 'typeorm';

/**
 * Entité représentant un utilisateur administrateur.
 * Un seul utilisateur admin est créé automatiquement au démarrage.
 */
@Entity('admin_users')
export class AdminUserEntity {
	@PrimaryGeneratedColumn('uuid')
	id: string;

	/** Nom d'utilisateur unique (défaut : "admin") */
	@Column({ type: 'text', unique: true })
	username: string;

	/** Hash bcrypt du mot de passe */
	@Column({ type: 'text' })
	passwordHash: string;

	@CreateDateColumn()
	createdAt: Date;
}
