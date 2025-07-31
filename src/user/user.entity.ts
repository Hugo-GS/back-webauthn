import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  nombre_usuario: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ type: 'blob', nullable: true })
  userHandle: Buffer;

  @Column({ type: 'text', nullable: true })
  currentChallenge?: string;
}
