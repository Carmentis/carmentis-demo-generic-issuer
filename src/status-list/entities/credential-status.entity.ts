import {
	Column,
	CreateDateColumn,
	Entity,
	ManyToOne,
	PrimaryGeneratedColumn,
} from 'typeorm';
import { SigningKeyEntity } from '../../keys/entities/signing-key.entity';

/**
 * Entité représentant le statut de révocation d'un credential émis.
 *
 * Chaque credential reçoit un index unique dans la liste de statut
 * de sa clé de signature. La liste de statut est un vecteur de bits :
 * bit à 0 = valide, bit à 1 = révoqué.
 */
@Entity('credential_statuses')
export class CredentialStatusEntity {
	@PrimaryGeneratedColumn('uuid')
	id: string;

	/** La clé de signature qui a émis ce credential */
	@ManyToOne(() => SigningKeyEntity, (key) => key.credentialStatuses, {
		onDelete: 'CASCADE',
	})
	signingKey: SigningKeyEntity;

	@Column()
	signingKeyId: string;

	/**
	 * Index dans la liste de statut (bitstring) de la clé de signature.
	 * Unique par clé de signature.
	 */
	@Column({ type: 'integer' })
	statusListIndex: number;

	/** true si le credential a été révoqué */
	@Column({ type: 'boolean', default: false })
	isRevoked: boolean;

	/**
	 * Identifiant unique du credential (claim `jti` du SD-JWT-VC).
	 * Stocké pour permettre la révocation par jti.
	 */
	@Column({ type: 'text', nullable: true })
	credentialId: string | null;

	@CreateDateColumn()
	issuedAt: Date;

	/** Date de révocation (null si non révoqué) */
	@Column({ type: 'datetime', nullable: true })
	revokedAt: Date | null;
}
