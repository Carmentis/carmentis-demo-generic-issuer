import {
	Column,
	CreateDateColumn,
	Entity,
	OneToMany,
	PrimaryGeneratedColumn,
	UpdateDateColumn,
} from 'typeorm';
import { ApiKeyEntity } from '../../auth/entities/api-key.entity';
import { CredentialStatusEntity } from '../../status-list/entities/credential-status.entity';

/**
 * Entité représentant une paire de clés Ed25519 gérée par le serveur.
 *
 * La clé privée est stockée chiffrée (AES-256-GCM) en base de données.
 * La clé publique est stockée en clair (JWK JSON).
 */
@Entity('signing_keys')
export class SigningKeyEntity {
	@PrimaryGeneratedColumn('uuid')
	id: string;

	/** Nom lisible par l'humain (ex: "Clé Université Paris") */
	@Column({ type: 'text' })
	name: string;

	/**
	 * Identifiant slug utilisé dans les URL : /api/<identifier>/*
	 * Ne doit contenir que des lettres minuscules, chiffres et tirets.
	 */
	@Column({ type: 'text', unique: true })
	identifier: string;

	/** Texte chiffré AES-256-GCM du JWK privé, encodé en base64 */
	@Column({ type: 'text' })
	encryptedPrivateKey: string;

	/** Vecteur d'initialisation AES-GCM (12 octets, base64) */
	@Column({ type: 'text' })
	encryptionIv: string;

	/** Étiquette d'authentification AES-GCM (16 octets, base64) */
	@Column({ type: 'text' })
	encryptionTag: string;

	/**
	 * JWK public sérialisé en JSON (non confidentiel).
	 * Pour les clés importées avec certificat, contient le champ `x5c`.
	 */
	@Column({ type: 'text' })
	publicKeyJwk: string;

	/**
	 * Algorithme de signature JOSE (ex: "EdDSA", "ES256", "RS256").
	 * Nullable pour compatibilité avec les anciennes lignes (déduit alors du JWK).
	 */
	@Column({ type: 'text', nullable: true })
	algorithm: string | null;

	/**
	 * Taille de la liste de statut en bits.
	 * Défaut : 131072 (= 16 384 octets ≈ 16 Ko, supporte 131 072 credentials).
	 */
	@Column({ type: 'integer', default: 131072 })
	statusListSize: number;

	/** Prochain index à allouer dans la liste de statut */
	@Column({ type: 'integer', default: 0 })
	statusListCurrent: number;

	@CreateDateColumn()
	createdAt: Date;

	@UpdateDateColumn()
	updatedAt: Date;

	/** Clés d'API associées à cette clé de signature */
	@OneToMany(() => ApiKeyEntity, (apiKey) => apiKey.signingKey)
	apiKeys: ApiKeyEntity[];

	/** Statuts des credentials émis avec cette clé */
	@OneToMany(() => CredentialStatusEntity, (status) => status.signingKey)
	credentialStatuses: CredentialStatusEntity[];
}
