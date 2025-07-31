import { IsOptional, IsString, IsNumber } from 'class-validator';

export class BeginAuthenticationDto {
  @IsOptional()
  @IsString({ message: 'User handle must be a string' })
  userHandle?: string;

  @IsOptional()
  @IsString({ message: 'Email must be a string' })
  email?: string;
}