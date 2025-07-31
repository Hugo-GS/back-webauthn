import { IsNumber, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class BeginRegistrationDto {
  @IsNumber({}, { message: 'User ID must be a valid number' })
  userId: number;

  @IsOptional()
  @IsString({ message: 'Device name must be a string' })
  @MinLength(1, { message: 'Device name must not be empty' })
  @MaxLength(100, { message: 'Device name cannot exceed 100 characters' })
  deviceName?: string;
}