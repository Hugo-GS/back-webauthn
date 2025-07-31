import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/types';

export class AuthenticationOptionsResponseDto {
  options: PublicKeyCredentialRequestOptionsJSON;
}

export class AuthenticationVerificationResponseDto {
  verified: boolean;
  token?: string;
  user?: {
    id: number;
    email: string;
    nombre_usuario: string;
  };
  message?: string;
}