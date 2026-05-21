import {
	Column,
	CreateDateColumn,
	Entity,
	ManyToOne,
	PrimaryGeneratedColumn,
} from 'typeorm';
import { SigningKeyEntity } from '../../keys/entities/signing-key.entity';

/**
 * Entité représentant une clé d'API.
 *
 * La valeur réelle de la clé n'est jamais stockée : seul un hash bcrypt
 * et un préfixe de 8 caractères (pour retrouver rapidement les candidats)
 * sont conservés en base.
 *
 * Chaque clé d'API est associée à une clé de signature (SigningKeyEntity).
 * Elle autorise uniquement les opérations sur cette clé de signature.
 */
@Entity('api_keys')
export class ApiKeyEntity {
	@PrimaryGeneratedColumn('uuid')
	id: string;

	/** Label descriptif (ex: "CI/CD pipeline prod") */
	@Column({ type: 'text' })
	label: string;

	/** Hash bcrypt de la clé d'API */
	@Column({ type: 'text' })
	keyHash: string;

	/**
	 * 8 premiers caractères de la clé d'API (en clair).
	 * Utilisé pour filtrer les candidats avant la comparaison bcrypt,
	 * évitant de hasher toutes les clés en base.
	 */
	@Column({ type: 'text' })
	keyPrefix: string;

	/** La clé de signature à laquelle cette clé d'API donne accès */
	@ManyToOne(() => SigningKeyEntity, (key) => key.apiKeys, {
		onDelete: 'CASCADE',
	})
	signingKey: SigningKeyEntity;

	@Column()
	signingKeyId: string;

	/** Indique si la clé a été révoquée */
	@Column({ type: 'boolean', default: false })
	isRevoked: boolean;

	@CreateDateColumn()
	createdAt: Date;

	/** Date de révocation (null si non révoquée) */
	@Column({ type: 'datetime', nullable: true })
	revokedAt: Date | null;
}
