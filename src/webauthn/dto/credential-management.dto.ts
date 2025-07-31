import { IsString, IsNotEmpty } from 'class-validator';

export class DeleteCredentialDto {
  @IsString({ message: 'Credential ID must be a string' })
  @IsNotEmpty({ message: 'Credential ID cannot be empty' })
  credentialId: string;
}

export class CredentialResponseDto {
  id: number;
  credentialID: string;
  deviceName?: string;
  credentialDeviceType: 'singleDevice' | 'multiDevice';
  credentialBackedUp: boolean;
  createdAt: Date;
  lastUsed: Date;
  transports?: string[];
}

export class CredentialListResponseDto {
  credentials: CredentialResponseDto[];
  count: number;
}