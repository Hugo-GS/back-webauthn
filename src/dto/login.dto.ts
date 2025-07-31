import { IsEmail, IsString } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Debe proporcionar un email válido' })
  email: string;

  @IsString({ message: 'La contraseña es requerida' })
  password: string;
}