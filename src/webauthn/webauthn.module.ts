import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { WebAuthnController } from './webauthn.controller';
import { WebAuthnService } from './webauthn.service';
import { WebAuthnCredential } from './webauthn-credential.entity';
import { WebAuthnConfigService } from './webauthn.config';
import { UserModule } from '../user/user.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([WebAuthnCredential]),
    UserModule,
    AuthModule,
  ],
  controllers: [WebAuthnController],
  providers: [WebAuthnService, WebAuthnConfigService],
  exports: [WebAuthnService],
})
export class WebAuthnModule {}