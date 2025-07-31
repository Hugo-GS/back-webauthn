import { IsNumber, IsObject, ValidateNested, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';
import { Type } from 'class-transformer';
import type { RegistrationResponseJSON } from '@simplewebauthn/types';
import { IsWebAuthnRegistrationResponse } from '../validators/webauthn.validators';

export class FinishRegistrationDto {
  @IsNumber({}, { message: 'User ID must be a valid number' })
  userId: number;

  @IsWebAuthnRegistrationResponse({ message: 'Response must be a valid WebAuthn registration response object' })
  response: RegistrationResponseJSON;

  @IsOptional()
  @IsString({ message: 'Device name must be a string' })
  @MinLength(1, { message: 'Device name must not be empty' })
  @MaxLength(100, { message: 'Device name cannot exceed 100 characters' })
  deviceName?: string;
}