import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../user/user.entity';

@Entity('webauthn_credentials')
export class WebAuthnCredential {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  credentialID: string; // Base64URL encoded credential ID

  @Column('text')
  credentialPublicKey: string; // Base64URL encoded public key

  @Column({ default: 0 })
  counter: number; // Signature counter for replay protection

  @Column()
  credentialDeviceType: 'singleDevice' | 'multiDevice';

  @Column({ default: false })
  credentialBackedUp: boolean;

  @Column({ type: 'text', nullable: true })
  transports?: string; // JSON array of transport methods

  @Column({ type: 'text', nullable: true })
  deviceName?: string; // User-friendly device name

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  lastUsed: Date;

  // Relationship with User
  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column()
  userId: number;
}