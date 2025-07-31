import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotFoundException } from '@nestjs/common';
import { WebAuthnService, WebAuthnRegistrationError, WebAuthnAuthenticationError } from './webauthn.service';
import { WebAuthnCredential } from './webauthn-credential.entity';
import { User } from '../user/user.entity';
import { WebAuthnConfigService } from './webauthn.config';
import { WebAuthnUtils } from './webauthn.utils';
import * as SimpleWebAuthn from '@simplewebauthn/server';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';

// Mock SimpleWebAuthn functions
jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

describe('WebAuthnService', () => {
  let service: WebAuthnService;
  let credentialRepository: jest.Mocked<Repository<WebAuthnCredential>>;
  let userRepository: jest.Mocked<Repository<User>>;
  let configService: jest.Mocked<WebAuthnConfigService>;

  const mockUser: User = {
    id: 1,
    nombre_usuario: 'testuser',
    email: 'test@example.com',
    password: 'hashedpassword',
    userHandle: Buffer.from('test-user-handle'),
    currentChallenge: undefined,
  };

  const mockCredential: WebAuthnCredential = {
    id: 1,
    credentialID: 'test-credential-id',
    credentialPublicKey: 'test-public-key',
    counter: 0,
    credentialDeviceType: 'singleDevice',
    credentialBackedUp: false,
    transports: '["usb","nfc"]',
    deviceName: 'Test Device',
    createdAt: new Date(),
    lastUsed: new Date(),
    user: mockUser,
    userId: 1,
  };

  const mockConfig = {
    rpName: 'Test RP',
    rpID: 'localhost',
    origin: 'http://localhost:3000',
    timeout: 60000,
    requireResidentKey: false,
    userVerification: 'preferred' as const,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WebAuthnService,
        {
          provide: getRepositoryToken(WebAuthnCredential),
          useValue: {
            find: jest.fn(),
            findOne: jest.fn(),
            save: jest.fn(),
            delete: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
          },
        },
        {
          provide: WebAuthnConfigService,
          useValue: {
            getConfig: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<WebAuthnService>(WebAuthnService);
    credentialRepository = module.get(getRepositoryToken(WebAuthnCredential));
    userRepository = module.get(getRepositoryToken(User));
    configService = module.get(WebAuthnConfigService);

    // Setup default mocks
    configService.getConfig.mockReturnValue(mockConfig);
    jest.clearAllMocks();
  });

  describe('generateRegistrationOptions', () => {
    it('should generate registration options for existing user', async () => {
      const mockOptions = {
        challenge: 'test-challenge',
        rp: { name: 'Test RP', id: 'localhost' },
        user: {
          id: 'test-user-handle',
          name: 'test@example.com',
          displayName: 'testuser',
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        timeout: 60000,
        excludeCredentials: [],
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
        attestation: 'none',
      };

      userRepository.findOne.mockResolvedValue(mockUser);
      credentialRepository.find.mockResolvedValue([]);
      (SimpleWebAuthn.generateRegistrationOptions as jest.Mock).mockResolvedValue(mockOptions);

      const result = await service.generateRegistrationOptions(1);

      expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
      expect(credentialRepository.find).toHaveBeenCalledWith({ where: { userId: 1 } });
      expect(SimpleWebAuthn.generateRegistrationOptions).toHaveBeenCalled();
      expect(userRepository.save).toHaveBeenCalledWith({
        ...mockUser,
        currentChallenge: 'test-challenge',
      });
      expect(result).toEqual(mockOptions);
    });

    it('should generate user handle if not exists', async () => {
      const userWithoutHandle = { ...mockUser, userHandle: undefined as any };
      const mockUserHandle = Buffer.from('new-user-handle');
      
      userRepository.findOne.mockResolvedValue(userWithoutHandle);
      credentialRepository.find.mockResolvedValue([]);
      jest.spyOn(WebAuthnUtils, 'generateUserHandle').mockReturnValue(mockUserHandle);
      (SimpleWebAuthn.generateRegistrationOptions as jest.Mock).mockResolvedValue({
        challenge: 'test-challenge',
      });

      await service.generateRegistrationOptions(1);

      expect(WebAuthnUtils.generateUserHandle).toHaveBeenCalled();
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithoutHandle,
        userHandle: mockUserHandle,
      });
    });

    it('should exclude existing credentials', async () => {
      const existingCredentials = [
        { ...mockCredential, credentialID: 'cred1', transports: '["usb"]' },
        { ...mockCredential, credentialID: 'cred2', transports: undefined },
      ];

      userRepository.findOne.mockResolvedValue(mockUser);
      credentialRepository.find.mockResolvedValue(existingCredentials);
      (SimpleWebAuthn.generateRegistrationOptions as jest.Mock).mockResolvedValue({
        challenge: 'test-challenge',
      });

      await service.generateRegistrationOptions(1);

      const generateOptionsCall = (SimpleWebAuthn.generateRegistrationOptions as jest.Mock).mock.calls[0][0];
      expect(generateOptionsCall.excludeCredentials).toEqual([
        { id: 'cred1', type: 'public-key', transports: ['usb'] },
        { id: 'cred2', type: 'public-key', transports: undefined },
      ]);
    });

    it('should throw NotFoundException for non-existent user', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(service.generateRegistrationOptions(999)).rejects.toThrow(NotFoundException);
      expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: 999 } });
    });
  });

  describe('verifyRegistration', () => {
    const mockRegistrationResponse: RegistrationResponseJSON = {
      id: 'test-credential-id',
      rawId: 'test-credential-id',
      response: {
        clientDataJSON: 'test-client-data',
        attestationObject: 'test-attestation',
        transports: ['usb', 'nfc'],
      },
      type: 'public-key',
      clientExtensionResults: {},
    };

    const mockVerificationResult = {
      verified: true,
      registrationInfo: {
        credential: {
          id: 'test-credential-id',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: 0,
        },
        credentialDeviceType: 'singleDevice' as const,
        credentialBackedUp: false,
      },
    };

    it('should verify registration and save credential', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'test-challenge' };
      
      userRepository.findOne.mockResolvedValue(userWithChallenge);
      credentialRepository.findOne.mockResolvedValue(null); // No existing credential
      credentialRepository.save.mockResolvedValue(mockCredential);
      (SimpleWebAuthn.verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockVerificationResult);
      jest.spyOn(WebAuthnUtils, 'uint8ArrayToBase64URL').mockReturnValue('test-public-key');

      const result = await service.verifyRegistration(1, mockRegistrationResponse, 'My Device');

      expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
      expect(SimpleWebAuthn.verifyRegistrationResponse).toHaveBeenCalledWith({
        response: mockRegistrationResponse,
        expectedChallenge: 'test-challenge',
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        requireUserVerification: false,
      });
      expect(credentialRepository.save).toHaveBeenCalled();
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithChallenge,
        currentChallenge: undefined,
      });
      expect(result.verified).toBe(true);
      expect(result.credential).toEqual(mockCredential);
    });

    it('should throw error for user without challenge', async () => {
      const userWithoutChallenge = { ...mockUser, currentChallenge: undefined };
      userRepository.findOne.mockResolvedValue(userWithoutChallenge); // No current challenge

      await expect(
        service.verifyRegistration(1, mockRegistrationResponse)
      ).rejects.toThrow(WebAuthnRegistrationError);
    });

    it('should throw error for non-existent user', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(
        service.verifyRegistration(999, mockRegistrationResponse)
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw error for existing credential', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'test-challenge' };
      
      userRepository.findOne.mockResolvedValue(userWithChallenge);
      credentialRepository.findOne.mockResolvedValue(mockCredential); // Existing credential
      (SimpleWebAuthn.verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockVerificationResult);

      await expect(
        service.verifyRegistration(1, mockRegistrationResponse)
      ).rejects.toThrow(WebAuthnRegistrationError);
    });

    it('should throw error for failed verification', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'test-challenge' };
      
      userRepository.findOne.mockResolvedValue(userWithChallenge);
      credentialRepository.findOne.mockResolvedValue(null);
      (SimpleWebAuthn.verifyRegistrationResponse as jest.Mock).mockResolvedValue({
        verified: false,
      });

      await expect(
        service.verifyRegistration(1, mockRegistrationResponse)
      ).rejects.toThrow(WebAuthnRegistrationError);

      // Should clear challenge on error
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithChallenge,
        currentChallenge: undefined,
      });
    });

    it('should handle verification errors and clear challenge', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'test-challenge' };
      
      userRepository.findOne.mockResolvedValue(userWithChallenge);
      (SimpleWebAuthn.verifyRegistrationResponse as jest.Mock).mockRejectedValue(
        new Error('Verification failed')
      );

      await expect(
        service.verifyRegistration(1, mockRegistrationResponse)
      ).rejects.toThrow(WebAuthnRegistrationError);

      // Should clear challenge on error
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithChallenge,
        currentChallenge: undefined,
      });
    });
  });

  describe('getUserCredentials', () => {
    it('should return user credentials ordered by creation date', async () => {
      const credentials = [mockCredential];
      credentialRepository.find.mockResolvedValue(credentials);

      const result = await service.getUserCredentials(1);

      expect(credentialRepository.find).toHaveBeenCalledWith({
        where: { userId: 1 },
        order: { createdAt: 'DESC' },
      });
      expect(result).toEqual(credentials);
    });

    it('should return empty array for user with no credentials', async () => {
      credentialRepository.find.mockResolvedValue([]);

      const result = await service.getUserCredentials(1);

      expect(result).toEqual([]);
    });
  });

  describe('generateAuthenticationOptions', () => {
    it('should generate authentication options without userHandle', async () => {
      const mockOptions = {
        challenge: 'auth-challenge',
        timeout: 60000,
        rpId: 'localhost',
        allowCredentials: undefined,
        userVerification: 'preferred',
      };

      (SimpleWebAuthn.generateAuthenticationOptions as jest.Mock).mockResolvedValue(mockOptions);

      const result = await service.generateAuthenticationOptions();

      expect(SimpleWebAuthn.generateAuthenticationOptions).toHaveBeenCalledWith({
        rpID: 'localhost',
        timeout: 60000,
        allowCredentials: undefined,
        userVerification: 'preferred',
      });
      expect(result).toEqual(mockOptions);
    });

    it('should generate authentication options with userHandle and store challenge', async () => {
      const userHandle = 'dGVzdC11c2VyLWhhbmRsZQ'; // base64url encoded 'test-user-handle'
      const mockOptions = {
        challenge: 'auth-challenge',
        timeout: 60000,
        rpId: 'localhost',
        allowCredentials: [
          { id: 'test-credential-id', type: 'public-key', transports: ['usb', 'nfc'] }
        ],
        userVerification: 'preferred',
      };

      userRepository.findOne.mockResolvedValue(mockUser);
      credentialRepository.find.mockResolvedValue([mockCredential]);
      (SimpleWebAuthn.generateAuthenticationOptions as jest.Mock).mockResolvedValue(mockOptions);

      const result = await service.generateAuthenticationOptions(userHandle);

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { userHandle: Buffer.from(userHandle, 'base64url') }
      });
      expect(credentialRepository.find).toHaveBeenCalledWith({ where: { userId: 1 } });
      expect(SimpleWebAuthn.generateAuthenticationOptions).toHaveBeenCalledWith({
        rpID: 'localhost',
        timeout: 60000,
        allowCredentials: [
          { id: 'test-credential-id', transports: ['usb', 'nfc'] }
        ],
        userVerification: 'preferred',
      });
      expect(userRepository.save).toHaveBeenCalledWith({
        ...mockUser,
        currentChallenge: 'auth-challenge',
      });
      expect(result).toEqual(mockOptions);
    });

    it('should handle non-existent user for userHandle', async () => {
      const userHandle = 'bm9uLWV4aXN0ZW50'; // base64url encoded 'non-existent'
      const mockOptions = {
        challenge: 'auth-challenge',
        allowCredentials: undefined,
      };

      userRepository.findOne.mockResolvedValue(null);
      (SimpleWebAuthn.generateAuthenticationOptions as jest.Mock).mockResolvedValue(mockOptions);

      const result = await service.generateAuthenticationOptions(userHandle);

      expect(result).toEqual(mockOptions);
      expect(userRepository.save).not.toHaveBeenCalled();
    });
  });

  describe('verifyAuthentication', () => {
    const mockAuthenticationResponse: AuthenticationResponseJSON = {
      id: 'test-credential-id',
      rawId: 'test-credential-id',
      response: {
        clientDataJSON: 'test-client-data',
        authenticatorData: 'test-authenticator-data',
        signature: 'test-signature',
        userHandle: 'test-user-handle',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };

    const mockAuthVerificationResult = {
      verified: true,
      authenticationInfo: {
        newCounter: 1,
        userVerified: true,
      },
    };

    it('should verify authentication successfully and update counter', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'auth-challenge' };
      const credentialWithUser = { ...mockCredential, user: userWithChallenge };

      credentialRepository.findOne.mockResolvedValue(credentialWithUser);
      (SimpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue(mockAuthVerificationResult);
      jest.spyOn(WebAuthnUtils, 'base64URLToUint8Array').mockReturnValue(new Uint8Array([1, 2, 3, 4]));

      const result = await service.verifyAuthentication(mockAuthenticationResponse);

      expect(credentialRepository.findOne).toHaveBeenCalledWith({
        where: { credentialID: 'test-credential-id' },
        relations: ['user'],
      });
      expect(SimpleWebAuthn.verifyAuthenticationResponse).toHaveBeenCalledWith({
        response: mockAuthenticationResponse,
        expectedChallenge: 'auth-challenge',
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        credential: {
          id: 'test-credential-id',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: 0,
        },
        requireUserVerification: false,
      });
      expect(credentialRepository.save).toHaveBeenCalledWith({
        ...credentialWithUser,
        counter: 1,
        lastUsed: expect.any(Date),
      });
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithChallenge,
        currentChallenge: undefined,
      });
      expect(result.verified).toBe(true);
      expect(result.user).toEqual(userWithChallenge);
    });

    it('should verify authentication with provided challenge', async () => {
      const userWithoutChallenge = { ...mockUser, currentChallenge: undefined };
      const credentialWithUser = { ...mockCredential, user: userWithoutChallenge };

      credentialRepository.findOne.mockResolvedValue(credentialWithUser);
      (SimpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue(mockAuthVerificationResult);
      jest.spyOn(WebAuthnUtils, 'base64URLToUint8Array').mockReturnValue(new Uint8Array([1, 2, 3, 4]));

      const result = await service.verifyAuthentication(mockAuthenticationResponse, 'provided-challenge');

      expect(SimpleWebAuthn.verifyAuthenticationResponse).toHaveBeenCalledWith({
        response: mockAuthenticationResponse,
        expectedChallenge: 'provided-challenge',
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        credential: {
          id: 'test-credential-id',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: 0,
        },
        requireUserVerification: false,
      });
      expect(result.verified).toBe(true);
    });

    it('should throw error for non-existent credential', async () => {
      credentialRepository.findOne.mockResolvedValue(null);

      await expect(
        service.verifyAuthentication(mockAuthenticationResponse)
      ).rejects.toThrow(WebAuthnAuthenticationError);
      expect(credentialRepository.findOne).toHaveBeenCalledWith({
        where: { credentialID: 'test-credential-id' },
        relations: ['user'],
      });
    });

    it('should throw error when no challenge is available', async () => {
      const userWithoutChallenge = { ...mockUser, currentChallenge: undefined };
      const credentialWithUser = { ...mockCredential, user: userWithoutChallenge };

      credentialRepository.findOne.mockResolvedValue(credentialWithUser);

      await expect(
        service.verifyAuthentication(mockAuthenticationResponse)
      ).rejects.toThrow(WebAuthnAuthenticationError);
    });

    it('should throw error for failed verification', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'auth-challenge' };
      const credentialWithUser = { ...mockCredential, user: userWithChallenge };

      credentialRepository.findOne.mockResolvedValue(credentialWithUser);
      (SimpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
        verified: false,
      });
      jest.spyOn(WebAuthnUtils, 'base64URLToUint8Array').mockReturnValue(new Uint8Array([1, 2, 3, 4]));

      await expect(
        service.verifyAuthentication(mockAuthenticationResponse)
      ).rejects.toThrow(WebAuthnAuthenticationError);

      // Should clear challenge on error
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithChallenge,
        currentChallenge: undefined,
      });
    });

    it('should detect and prevent replay attacks with invalid counter', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'auth-challenge' };
      const credentialWithHighCounter = { ...mockCredential, counter: 5, user: userWithChallenge };

      credentialRepository.findOne.mockResolvedValue(credentialWithHighCounter);
      (SimpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
        verified: true,
        authenticationInfo: {
          newCounter: 3, // Lower than current counter - replay attack
          userVerified: true,
        },
      });
      jest.spyOn(WebAuthnUtils, 'base64URLToUint8Array').mockReturnValue(new Uint8Array([1, 2, 3, 4]));

      await expect(
        service.verifyAuthentication(mockAuthenticationResponse)
      ).rejects.toThrow(WebAuthnAuthenticationError);

      // Should clear challenge on error
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithChallenge,
        currentChallenge: undefined,
      });
    });

    it('should handle verification errors and clear challenge', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'auth-challenge' };
      const credentialWithUser = { ...mockCredential, user: userWithChallenge };

      credentialRepository.findOne.mockResolvedValue(credentialWithUser);
      (SimpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockRejectedValue(
        new Error('Verification failed')
      );
      jest.spyOn(WebAuthnUtils, 'base64URLToUint8Array').mockReturnValue(new Uint8Array([1, 2, 3, 4]));

      await expect(
        service.verifyAuthentication(mockAuthenticationResponse)
      ).rejects.toThrow(WebAuthnAuthenticationError);

      // Should clear challenge on error
      expect(userRepository.save).toHaveBeenCalledWith({
        ...userWithChallenge,
        currentChallenge: undefined,
      });
    });

    it('should handle equal counter values as replay attack', async () => {
      const userWithChallenge = { ...mockUser, currentChallenge: 'auth-challenge' };
      const credentialWithUser = { ...mockCredential, counter: 5, user: userWithChallenge };

      credentialRepository.findOne.mockResolvedValue(credentialWithUser);
      (SimpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
        verified: true,
        authenticationInfo: {
          newCounter: 5, // Equal to current counter - replay attack
          userVerified: true,
        },
      });
      jest.spyOn(WebAuthnUtils, 'base64URLToUint8Array').mockReturnValue(new Uint8Array([1, 2, 3, 4]));

      await expect(
        service.verifyAuthentication(mockAuthenticationResponse)
      ).rejects.toThrow(WebAuthnAuthenticationError);
    });
  });

  describe('deleteCredential', () => {
    it('should delete credential and return true', async () => {
      credentialRepository.delete.mockResolvedValue({ affected: 1, raw: {} });

      const result = await service.deleteCredential(1, 'test-credential-id');

      expect(credentialRepository.delete).toHaveBeenCalledWith({
        userId: 1,
        credentialID: 'test-credential-id',
      });
      expect(result).toBe(true);
    });

    it('should return false when credential not found', async () => {
      credentialRepository.delete.mockResolvedValue({ affected: 0, raw: {} });

      const result = await service.deleteCredential(1, 'non-existent-id');

      expect(result).toBe(false);
    });
  });
});