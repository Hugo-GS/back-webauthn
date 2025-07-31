import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyAuthenticationResponseOpts,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/types';
import { WebAuthnCredential } from './webauthn-credential.entity';
import { User } from '../user/user.entity';
import { WebAuthnConfigService } from './webauthn.config';
import { WebAuthnUtils } from './webauthn.utils';

export class WebAuthnRegistrationError extends BadRequestException {
  constructor(message: string) {
    super(`WebAuthn Registration Failed: ${message}`);
  }
}

export class WebAuthnAuthenticationError extends BadRequestException {
  constructor(message: string) {
    super(`WebAuthn Authentication Failed: ${message}`);
  }
}

@Injectable()
export class WebAuthnService {
  constructor(
    @InjectRepository(WebAuthnCredential)
    private credentialRepository: Repository<WebAuthnCredential>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private webAuthnConfig: WebAuthnConfigService,
  ) {}

  /**
   * Generate registration options for WebAuthn credential registration
   * @param userId - The user ID to generate options for
   * @returns PublicKeyCredentialCreationOptionsJSON
   */
  async generateRegistrationOptions(userId: number): Promise<PublicKeyCredentialCreationOptionsJSON> {
    // Find the user
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Generate user handle if not exists
    if (!user.userHandle) {
      user.userHandle = WebAuthnUtils.generateUserHandle();
      await this.userRepository.save(user);
    }

    // Get existing credentials for this user to exclude them
    const existingCredentials = await this.credentialRepository.find({
      where: { userId },
    });

    const excludeCredentials = existingCredentials.map(cred => ({
      id: cred.credentialID,
      type: 'public-key' as const,
      transports: cred.transports ? JSON.parse(cred.transports) : undefined,
    }));

    const config = this.webAuthnConfig.getConfig();

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: config.rpName,
      rpID: config.rpID,
      userID: user.userHandle,
      userName: user.email,
      userDisplayName: user.nombre_usuario,
      timeout: config.timeout,
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        residentKey: config.requireResidentKey ? 'required' : 'preferred',
        userVerification: config.userVerification,
      },
      supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
    };

    const options = await generateRegistrationOptions(opts);

    // Store the challenge for verification
    user.currentChallenge = options.challenge;
    await this.userRepository.save(user);

    return options;
  }

  /**
   * Verify registration response and store the credential
   * @param userId - The user ID
   * @param response - The registration response from the client
   * @param deviceName - Optional device name for the credential
   * @returns Object with verification result and credential if successful
   */
  async verifyRegistration(
    userId: number,
    response: RegistrationResponseJSON,
    deviceName?: string,
  ): Promise<{ verified: boolean; credential?: WebAuthnCredential }> {
    // Find the user
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.currentChallenge) {
      throw new WebAuthnRegistrationError('No challenge found for user');
    }

    const config = this.webAuthnConfig.getConfig();

    const opts: VerifyRegistrationResponseOpts = {
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: config.userVerification === 'required',
    };

    try {
      const verification = await verifyRegistrationResponse(opts);

      if (!verification.verified || !verification.registrationInfo) {
        throw new WebAuthnRegistrationError('Registration verification failed');
      }

      const { registrationInfo } = verification;

      // Check if credential already exists
      const existingCredential = await this.credentialRepository.findOne({
        where: { credentialID: registrationInfo.credential.id },
      });

      if (existingCredential) {
        throw new WebAuthnRegistrationError('Credential already registered');
      }

      // Create and save the new credential
      const credential = new WebAuthnCredential();
      credential.credentialID = registrationInfo.credential.id;
      credential.credentialPublicKey = WebAuthnUtils.uint8ArrayToBase64URL(registrationInfo.credential.publicKey);
      credential.counter = registrationInfo.credential.counter;
      credential.credentialDeviceType = registrationInfo.credentialDeviceType;
      credential.credentialBackedUp = registrationInfo.credentialBackedUp;
      credential.userId = userId;
      credential.user = user;
      credential.deviceName = deviceName || 'Unknown Device';

      // Store transports if available
      if (response.response.transports) {
        credential.transports = JSON.stringify(response.response.transports);
      }

      const savedCredential = await this.credentialRepository.save(credential);

      // Clear the challenge
      user.currentChallenge = undefined;
      await this.userRepository.save(user);

      return {
        verified: true,
        credential: savedCredential,
      };
    } catch (error) {
      // Clear the challenge on error
      user.currentChallenge = undefined;
      await this.userRepository.save(user);

      if (error instanceof WebAuthnRegistrationError) {
        throw error;
      }

      throw new WebAuthnRegistrationError(
        error instanceof Error ? error.message : 'Unknown registration error',
      );
    }
  }

  /**
   * Generate authentication options for WebAuthn authentication
   * @param userHandle - Optional user handle to filter credentials
   * @param email - Optional email to find user and filter credentials
   * @returns PublicKeyCredentialRequestOptionsJSON
   */
  async generateAuthenticationOptions(userHandle?: string, email?: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    console.log('🔍 [WebAuthn Service] Generating authentication options:', {
      userHandle,
      email,
      hasUserHandle: !!userHandle,
      hasEmail: !!email
    });

    const config = this.webAuthnConfig.getConfig();
    let allowCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[] | undefined;
    let user: User | null = null;

    // Try to find user by userHandle first, then by email
    if (userHandle) {
      console.log('🔍 [WebAuthn Service] Looking up user by userHandle...');
      user = await this.userRepository.findOne({ 
        where: { userHandle: Buffer.from(userHandle, 'base64url') } 
      });
    } else if (email) {
      console.log('🔍 [WebAuthn Service] Looking up user by email:', email);
      user = await this.userRepository.findOne({ 
        where: { email: email } 
      });
    }

    console.log('🔍 [WebAuthn Service] User lookup result:', {
      userFound: !!user,
      userId: user?.id,
      userEmail: user?.email,
      hasUserHandle: !!user?.userHandle
    });

    // If we found a user, get their credentials
    if (user) {
      const userCredentials = await this.credentialRepository.find({
        where: { userId: user.id },
      });

      console.log('🔍 [WebAuthn Service] User credentials found:', {
        userId: user.id,
        credentialsCount: userCredentials.length,
        credentials: userCredentials.map(cred => ({
          id: cred.id,
          credentialID: cred.credentialID,
          deviceName: cred.deviceName,
          transports: cred.transports
        }))
      });

      allowCredentials = userCredentials.map(cred => ({
        id: cred.credentialID,
        transports: cred.transports ? JSON.parse(cred.transports) as AuthenticatorTransportFuture[] : undefined,
      }));
    } else {
      console.log('⚠️ [WebAuthn Service] No user found - authentication will be usernameless');
    }

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: config.rpID,
      timeout: config.timeout,
      allowCredentials,
      userVerification: config.userVerification,
    };

    const options = await generateAuthenticationOptions(opts);

    // Store the challenge in the user if we found one
    if (user) {
      user.currentChallenge = options.challenge;
      await this.userRepository.save(user);
    }

    return options;
  }

  /**
   * Verify authentication response and return user if successful
   * @param response - The authentication response from the client
   * @param expectedChallenge - The expected challenge (optional, will be looked up if not provided)
   * @returns Object with verification result and user if successful
   */
  async verifyAuthentication(
    response: AuthenticationResponseJSON,
    expectedChallenge?: string,
  ): Promise<{ verified: boolean; user?: User }> {
    const config = this.webAuthnConfig.getConfig();

    // Find the credential by ID
    const credential = await this.credentialRepository.findOne({
      where: { credentialID: response.id },
      relations: ['user'],
    });

    if (!credential) {
      throw new WebAuthnAuthenticationError('Credential not found');
    }

    const user = credential.user;
    
    // Use provided challenge or get from user's stored challenge
    const challenge = expectedChallenge || user.currentChallenge;
    if (!challenge) {
      throw new WebAuthnAuthenticationError('No challenge found for authentication');
    }

    const opts: VerifyAuthenticationResponseOpts = {
      response,
      expectedChallenge: challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      credential: {
        id: credential.credentialID,
        publicKey: WebAuthnUtils.base64URLToUint8Array(credential.credentialPublicKey),
        counter: credential.counter,
      },
      requireUserVerification: config.userVerification === 'required',
    };

    try {
      const verification = await verifyAuthenticationResponse(opts);

      if (!verification.verified) {
        throw new WebAuthnAuthenticationError('Authentication verification failed');
      }

      // Update credential counter to prevent replay attacks
      const newCounter = verification.authenticationInfo.newCounter;
      
      console.log('🔍 [WebAuthn Service] Counter validation:', {
        credentialId: credential.credentialID,
        currentCounter: credential.counter,
        newCounter: newCounter,
        isValid: newCounter > credential.counter,
        userId: user.id
      });
      
      // Check if counter validation is disabled for development
      const disableCounterCheck = process.env.WEBAUTHN_DISABLE_COUNTER_CHECK === 'true';
      
      console.log('🔧 [WebAuthn Service] Counter check configuration:', {
        WEBAUTHN_DISABLE_COUNTER_CHECK: process.env.WEBAUTHN_DISABLE_COUNTER_CHECK,
        disableCounterCheck: disableCounterCheck,
        willSkipValidation: disableCounterCheck && newCounter <= credential.counter
      });
      
      if (newCounter <= credential.counter && !disableCounterCheck) {
        console.error('❌ [WebAuthn Service] Counter validation failed - possible replay attack:', {
          credentialId: credential.credentialID,
          currentCounter: credential.counter,
          newCounter: newCounter,
          difference: newCounter - credential.counter,
          userId: user.id
        });
        throw new WebAuthnAuthenticationError('Invalid counter value - possible replay attack');
      } else if (newCounter <= credential.counter && disableCounterCheck) {
        console.warn('⚠️ [WebAuthn Service] Counter validation failed but DISABLED for development:', {
          credentialId: credential.credentialID,
          currentCounter: credential.counter,
          newCounter: newCounter,
          difference: newCounter - credential.counter,
          userId: user.id,
          note: 'Counter check disabled - NOT SAFE for production!'
        });
      }

      // Update credential with new counter and last used timestamp
      credential.counter = newCounter;
      credential.lastUsed = new Date();
      await this.credentialRepository.save(credential);

      // Clear the challenge
      user.currentChallenge = undefined;
      await this.userRepository.save(user);

      return {
        verified: true,
        user,
      };
    } catch (error) {
      // Clear the challenge on error
      user.currentChallenge = undefined;
      await this.userRepository.save(user);

      if (error instanceof WebAuthnAuthenticationError) {
        throw error;
      }

      throw new WebAuthnAuthenticationError(
        error instanceof Error ? error.message : 'Unknown authentication error',
      );
    }
  }

  /**
   * Get all credentials for a user
   * @param userId - The user ID
   * @returns Array of WebAuthnCredential
   */
  async getUserCredentials(userId: number): Promise<WebAuthnCredential[]> {
    return this.credentialRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Delete a credential for a user
   * @param userId - The user ID
   * @param credentialId - The credential ID to delete
   * @returns True if deleted, false if not found
   */
  async deleteCredential(userId: number, credentialId: string): Promise<boolean> {
    const result = await this.credentialRepository.delete({
      userId,
      credentialID: credentialId,
    });

    return (result.affected ?? 0) > 0;
  }
}