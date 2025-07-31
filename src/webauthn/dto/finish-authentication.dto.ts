import { IsObject, IsOptional, IsString } from 'class-validator';
import type { AuthenticationResponseJSON } from '@simplewebauthn/types';
import { IsWebAuthnAuthenticationResponse } from '../validators/webauthn.validators';

export class FinishAuthenticationDto {
  @IsWebAuthnAuthenticationResponse({ message: 'Response must be a valid WebAuthn authentication response object' })
  response: AuthenticationResponseJSON;

  @IsOptional()
  @IsString({ message: 'Expected challenge must be a string' })
  expectedChallenge?: string;
}