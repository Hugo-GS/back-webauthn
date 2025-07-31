import { DataSource } from 'typeorm';
import { User } from './user/user.entity';
import { WebAuthnCredential } from './webauthn/webauthn-credential.entity';

export const AppDataSource = new DataSource({
  type: 'sqlite',
  database: 'db.sqlite',
  entities: [User, WebAuthnCredential],
  migrations: ['src/migrations/*.ts'],
  synchronize: false, // Set to false when using migrations
  logging: false,
});