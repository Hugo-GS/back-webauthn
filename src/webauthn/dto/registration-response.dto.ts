import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/types';

export class RegistrationOptionsResponseDto {
  options: PublicKeyCredentialCreationOptionsJSON;
}

export class RegistrationVerificationResponseDto {
  verified: boolean;
  credentialId?: string;
  message?: string;
}