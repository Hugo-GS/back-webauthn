import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  Request,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  UsePipes,
  UseGuards,
  BadRequestException,
  NotFoundException,
  InternalServerErrorException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { WebAuthnService, WebAuthnRegistrationError, WebAuthnAuthenticationError } from './webauthn.service';
import { AuthService } from '../auth/auth.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { BeginRegistrationDto } from './dto/begin-registration.dto';
import { FinishRegistrationDto } from './dto/finish-registration.dto';
import { BeginAuthenticationDto } from './dto/begin-authentication.dto';
import { FinishAuthenticationDto } from './dto/finish-authentication.dto';
import { CredentialListResponseDto, CredentialResponseDto } from './dto/credential-management.dto';
import { RegistrationOptionsResponseDto, RegistrationVerificationResponseDto } from './dto/registration-response.dto';
import { AuthenticationOptionsResponseDto, AuthenticationVerificationResponseDto } from './dto/authentication-response.dto';

@Controller('webauthn')
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class WebAuthnController {
  constructor(
    private readonly webAuthnService: WebAuthnService,
    private readonly authService: AuthService,
  ) {}

  /**
   * Begin WebAuthn registration process
   * POST /webauthn/register/begin
   */
  @Post('register/begin')
  @HttpCode(HttpStatus.OK)
  async beginRegistration(@Body() beginRegistrationDto: BeginRegistrationDto): Promise<RegistrationOptionsResponseDto> {
    console.log('🚀 [WebAuthn] BEGIN REGISTRATION - Request received:', {
      userId: beginRegistrationDto.userId,
      deviceName: beginRegistrationDto.deviceName,
      timestamp: new Date().toISOString()
    });

    try {
      const options = await this.webAuthnService.generateRegistrationOptions(beginRegistrationDto.userId);
      
      const response = {
        options,
      };

      console.log('✅ [WebAuthn] BEGIN REGISTRATION - Response sent:', {
        userId: beginRegistrationDto.userId,
        challenge: options.challenge,
        rpId: options.rp.id,
        rpName: options.rp.name,
        userName: options.user.name,
        userDisplayName: options.user.displayName,
        excludeCredentialsCount: options.excludeCredentials?.length || 0,
        timestamp: new Date().toISOString()
      });
      
      return response;
    } catch (error) {
      console.error('❌ [WebAuthn] BEGIN REGISTRATION - Error:', {
        userId: beginRegistrationDto.userId,
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });

      if (error instanceof NotFoundException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Failed to generate registration options');
    }
  }

  /**
   * Finish WebAuthn registration process
   * POST /webauthn/register/finish
   */
  @Post('register/finish')
  @HttpCode(HttpStatus.CREATED)
  async finishRegistration(@Body() finishRegistrationDto: FinishRegistrationDto): Promise<RegistrationVerificationResponseDto> {
    console.log('🚀 [WebAuthn] FINISH REGISTRATION - Request received:', {
      userId: finishRegistrationDto.userId,
      deviceName: finishRegistrationDto.deviceName,
      responseId: finishRegistrationDto.response?.id,
      responseType: finishRegistrationDto.response?.type,
      hasClientDataJSON: !!finishRegistrationDto.response?.response?.clientDataJSON,
      hasAttestationObject: !!finishRegistrationDto.response?.response?.attestationObject,
      transports: finishRegistrationDto.response?.response?.transports,
      timestamp: new Date().toISOString()
    });

    try {
      const result = await this.webAuthnService.verifyRegistration(
        finishRegistrationDto.userId,
        finishRegistrationDto.response,
        finishRegistrationDto.deviceName,
      );

      let response: RegistrationVerificationResponseDto;

      if (result.verified && result.credential) {
        response = {
          verified: true,
          credentialId: result.credential.credentialID,
          message: 'Registration successful',
        };

        console.log('✅ [WebAuthn] FINISH REGISTRATION - Success:', {
          userId: finishRegistrationDto.userId,
          credentialId: result.credential.credentialID,
          deviceName: result.credential.deviceName,
          credentialDeviceType: result.credential.credentialDeviceType,
          credentialBackedUp: result.credential.credentialBackedUp,
          timestamp: new Date().toISOString()
        });
      } else {
        response = {
          verified: false,
          message: 'Registration verification failed',
        };

        console.log('⚠️ [WebAuthn] FINISH REGISTRATION - Verification failed:', {
          userId: finishRegistrationDto.userId,
          verified: result.verified,
          hasCredential: !!result.credential,
          timestamp: new Date().toISOString()
        });
      }

      return response;
    } catch (error) {
      console.error('❌ [WebAuthn] FINISH REGISTRATION - Error:', {
        userId: finishRegistrationDto.userId,
        error: error.message,
        errorType: error.constructor.name,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });

      if (error instanceof NotFoundException) {
        throw error;
      }
      
      if (error instanceof WebAuthnRegistrationError) {
        throw new BadRequestException(error.message);
      }
      
      throw new InternalServerErrorException('Failed to complete registration');
    }
  }

  /**
   * Begin WebAuthn authentication process
   * POST /webauthn/authenticate/begin
   */
  @Post('authenticate/begin')
  @HttpCode(HttpStatus.OK)
  async beginAuthentication(@Body() beginAuthenticationDto: BeginAuthenticationDto): Promise<AuthenticationOptionsResponseDto> {
    console.log('🚀 [WebAuthn] BEGIN AUTHENTICATION - Request received:', {
      userHandle: beginAuthenticationDto.userHandle,
      email: beginAuthenticationDto.email,
      hasUserHandle: !!beginAuthenticationDto.userHandle,
      hasEmail: !!beginAuthenticationDto.email,
      timestamp: new Date().toISOString()
    });

    try {
      const options = await this.webAuthnService.generateAuthenticationOptions(
        beginAuthenticationDto.userHandle,
        beginAuthenticationDto.email
      );
      
      const response = {
        options,
      };

      console.log('✅ [WebAuthn] BEGIN AUTHENTICATION - Response sent:', {
        userHandle: beginAuthenticationDto.userHandle,
        challenge: options.challenge,
        rpId: options.rpId,
        allowCredentialsCount: options.allowCredentials?.length || 0,
        userVerification: options.userVerification,
        timeout: options.timeout,
        timestamp: new Date().toISOString()
      });
      
      return response;
    } catch (error) {
      console.error('❌ [WebAuthn] BEGIN AUTHENTICATION - Error:', {
        userHandle: beginAuthenticationDto.userHandle,
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });
      
      throw new InternalServerErrorException('Failed to generate authentication options');
    }
  }

  /**
   * Finish WebAuthn authentication process
   * POST /webauthn/authenticate/finish
   */
  @Post('authenticate/finish')
  @HttpCode(HttpStatus.OK)
  async finishAuthentication(@Body() finishAuthenticationDto: FinishAuthenticationDto): Promise<AuthenticationVerificationResponseDto> {
    console.log('🚀 [WebAuthn] FINISH AUTHENTICATION - Request received:', {
      responseId: finishAuthenticationDto.response?.id,
      responseType: finishAuthenticationDto.response?.type,
      hasClientDataJSON: !!finishAuthenticationDto.response?.response?.clientDataJSON,
      hasAuthenticatorData: !!finishAuthenticationDto.response?.response?.authenticatorData,
      hasSignature: !!finishAuthenticationDto.response?.response?.signature,
      userHandle: finishAuthenticationDto.response?.response?.userHandle,
      expectedChallenge: finishAuthenticationDto.expectedChallenge,
      timestamp: new Date().toISOString()
    });

    try {
      const result = await this.webAuthnService.verifyAuthentication(
        finishAuthenticationDto.response,
        finishAuthenticationDto.expectedChallenge,
      );

      if (result.verified && result.user) {
        // Generate JWT token using the existing AuthService.login method
        const tokenResult = await this.authService.login(result.user);
        
        const response = {
          verified: true,
          token: tokenResult.access_token,
          user: {
            id: result.user.id,
            email: result.user.email,
            nombre_usuario: result.user.nombre_usuario,
          },
          message: 'Authentication successful',
        };

        console.log('✅ [WebAuthn] FINISH AUTHENTICATION - Success:', {
          userId: result.user.id,
          email: result.user.email,
          nombre_usuario: result.user.nombre_usuario,
          credentialId: finishAuthenticationDto.response?.id,
          hasToken: !!tokenResult.access_token,
          timestamp: new Date().toISOString()
        });

        return response;
      } else {
        console.log('⚠️ [WebAuthn] FINISH AUTHENTICATION - Verification failed:', {
          verified: result.verified,
          hasUser: !!result.user,
          credentialId: finishAuthenticationDto.response?.id,
          timestamp: new Date().toISOString()
        });

        throw new UnauthorizedException('Authentication verification failed');
      }
    } catch (error) {
      console.error('❌ [WebAuthn] FINISH AUTHENTICATION - Error:', {
        credentialId: finishAuthenticationDto.response?.id,
        error: error.message,
        errorType: error.constructor.name,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });

      if (error instanceof WebAuthnAuthenticationError) {
        throw new UnauthorizedException(error.message);
      }
      
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Failed to complete authentication');
    }
  }

  /**
   * Get user's WebAuthn credentials
   * GET /webauthn/credentials
   */
  @Get('credentials')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getUserCredentials(@Request() req: any): Promise<CredentialListResponseDto> {
    console.log('🚀 [WebAuthn] GET CREDENTIALS - Request received:', {
      userId: req.user.userId,
      userEmail: req.user.email,
      timestamp: new Date().toISOString()
    });

    try {
      const userId = req.user.userId;
      const credentials = await this.webAuthnService.getUserCredentials(userId);
      
      const credentialDtos: CredentialResponseDto[] = credentials.map(credential => ({
        id: credential.id,
        credentialID: credential.credentialID,
        deviceName: credential.deviceName,
        credentialDeviceType: credential.credentialDeviceType,
        credentialBackedUp: credential.credentialBackedUp,
        createdAt: credential.createdAt,
        lastUsed: credential.lastUsed,
        transports: credential.transports ? JSON.parse(credential.transports) : undefined,
      }));

      const response = {
        credentials: credentialDtos,
        count: credentialDtos.length,
      };

      console.log('✅ [WebAuthn] GET CREDENTIALS - Response sent:', {
        userId: userId,
        credentialsCount: credentialDtos.length,
        credentials: credentialDtos.map(cred => ({
          id: cred.id,
          credentialID: cred.credentialID,
          deviceName: cred.deviceName,
          credentialDeviceType: cred.credentialDeviceType,
          credentialBackedUp: cred.credentialBackedUp,
          createdAt: cred.createdAt,
          lastUsed: cred.lastUsed,
          transports: cred.transports
        })),
        timestamp: new Date().toISOString()
      });

      return response;
    } catch (error) {
      console.error('❌ [WebAuthn] GET CREDENTIALS - Error:', {
        userId: req.user.userId,
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });
      
      throw new InternalServerErrorException('Failed to retrieve credentials');
    }
  }

  /**
   * Delete a WebAuthn credential
   * DELETE /webauthn/credentials/:id
   */
  @Delete('credentials/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteCredential(@Request() req: any, @Param('id') credentialId: string): Promise<void> {
    console.log('🚀 [WebAuthn] DELETE CREDENTIAL - Request received:', {
      userId: req.user.userId,
      userEmail: req.user.email,
      credentialId: credentialId,
      hasCredentialId: !!credentialId,
      timestamp: new Date().toISOString()
    });

    try {
      const userId = req.user.userId;
      
      // Validate that the credential ID is provided
      if (!credentialId || credentialId.trim() === '') {
        console.log('⚠️ [WebAuthn] DELETE CREDENTIAL - Invalid credential ID:', {
          userId: userId,
          credentialId: credentialId,
          timestamp: new Date().toISOString()
        });
        throw new BadRequestException('Credential ID is required');
      }

      // First, verify that the credential belongs to the authenticated user
      const userCredentials = await this.webAuthnService.getUserCredentials(userId);
      const credentialExists = userCredentials.some(cred => cred.credentialID === credentialId);
      
      console.log('🔍 [WebAuthn] DELETE CREDENTIAL - Credential ownership check:', {
        userId: userId,
        credentialId: credentialId,
        userCredentialsCount: userCredentials.length,
        credentialExists: credentialExists,
        userCredentialIds: userCredentials.map(cred => cred.credentialID),
        timestamp: new Date().toISOString()
      });
      
      if (!credentialExists) {
        console.log('⚠️ [WebAuthn] DELETE CREDENTIAL - Credential not found or not owned by user:', {
          userId: userId,
          credentialId: credentialId,
          timestamp: new Date().toISOString()
        });
        throw new NotFoundException('Credential not found or does not belong to user');
      }

      // Delete the credential
      const deleted = await this.webAuthnService.deleteCredential(userId, credentialId);
      
      if (!deleted) {
        console.log('⚠️ [WebAuthn] DELETE CREDENTIAL - Credential not found during deletion:', {
          userId: userId,
          credentialId: credentialId,
          timestamp: new Date().toISOString()
        });
        throw new NotFoundException('Credential not found');
      }

      console.log('✅ [WebAuthn] DELETE CREDENTIAL - Success:', {
        userId: userId,
        credentialId: credentialId,
        deleted: deleted,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof BadRequestException || 
          error instanceof NotFoundException || 
          error instanceof ForbiddenException) {
        throw error;
      }
      
      console.error('❌ [WebAuthn] DELETE CREDENTIAL - Error:', {
        userId: req.user.userId,
        credentialId: credentialId,
        error: error.message,
        errorType: error.constructor.name,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });
      
      throw new InternalServerErrorException('Failed to delete credential');
    }
  }
}