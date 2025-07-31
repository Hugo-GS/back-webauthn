import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { WebAuthnController } from './webauthn.controller';
import { WebAuthnService, WebAuthnRegistrationError, WebAuthnAuthenticationError } from './webauthn.service';
import { AuthService } from '../auth/auth.service';
import { BeginRegistrationDto } from './dto/begin-registration.dto';
import { FinishRegistrationDto } from './dto/finish-registration.dto';
import { BeginAuthenticationDto } from './dto/begin-authentication.dto';
import { FinishAuthenticationDto } from './dto/finish-authentication.dto';
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';

describe('WebAuthnController', () => {
  let controller: WebAuthnController;
  let service: WebAuthnService;
  let authService: AuthService;

  const mockWebAuthnService = {
    generateRegistrationOptions: jest.fn(),
    verifyRegistration: jest.fn(),
    generateAuthenticationOptions: jest.fn(),
    verifyAuthentication: jest.fn(),
    getUserCredentials: jest.fn(),
    deleteCredential: jest.fn(),
  };

  const mockAuthService = {
    login: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [WebAuthnController],
      providers: [
        {
          provide: WebAuthnService,
          useValue: mockWebAuthnService,
        },
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<WebAuthnController>(WebAuthnController);
    service = module.get<WebAuthnService>(WebAuthnService);
    authService = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('beginRegistration', () => {
    it('should return registration options successfully', async () => {
      const userId = 1;
      const mockOptions: PublicKeyCredentialCreationOptionsJSON = {
        rp: { name: 'Test App', id: 'localhost' },
        user: {
          id: 'dGVzdA',
          name: 'test@example.com',
          displayName: 'Test User',
        },
        challenge: 'test-challenge',
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        timeout: 60000,
        attestation: 'none',
        excludeCredentials: [],
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
      };

      mockWebAuthnService.generateRegistrationOptions.mockResolvedValue(mockOptions);

      const dto: BeginRegistrationDto = { userId };
      const result = await controller.beginRegistration(dto);

      expect(result).toEqual({ options: mockOptions });
      expect(service.generateRegistrationOptions).toHaveBeenCalledWith(userId);
    });

    it('should throw NotFoundException when user not found', async () => {
      const userId = 999;
      const dto: BeginRegistrationDto = { userId };

      mockWebAuthnService.generateRegistrationOptions.mockRejectedValue(
        new NotFoundException('User not found')
      );

      await expect(controller.beginRegistration(dto)).rejects.toThrow(NotFoundException);
      expect(service.generateRegistrationOptions).toHaveBeenCalledWith(userId);
    });

    it('should throw InternalServerErrorException for other errors', async () => {
      const userId = 1;
      const dto: BeginRegistrationDto = { userId };

      mockWebAuthnService.generateRegistrationOptions.mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(controller.beginRegistration(dto)).rejects.toThrow(InternalServerErrorException);
      expect(service.generateRegistrationOptions).toHaveBeenCalledWith(userId);
    });
  });

  describe('finishRegistration', () => {
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

    it('should return successful verification result', async () => {
      const userId = 1;
      const deviceName = 'Test Device';
      const mockCredential = {
        id: 1,
        credentialID: 'test-credential-id',
        userId,
        deviceName,
        createdAt: new Date(),
        lastUsed: new Date(),
      };

      mockWebAuthnService.verifyRegistration.mockResolvedValue({
        verified: true,
        credential: mockCredential,
      });

      const dto: FinishRegistrationDto = {
        userId,
        response: mockRegistrationResponse,
        deviceName,
      };

      const result = await controller.finishRegistration(dto);

      expect(result).toEqual({
        verified: true,
        credentialId: 'test-credential-id',
        message: 'Registration successful',
      });
      expect(service.verifyRegistration).toHaveBeenCalledWith(userId, mockRegistrationResponse, deviceName);
    });

    it('should return failed verification result', async () => {
      const userId = 1;

      mockWebAuthnService.verifyRegistration.mockResolvedValue({
        verified: false,
      });

      const dto: FinishRegistrationDto = {
        userId,
        response: mockRegistrationResponse,
      };

      const result = await controller.finishRegistration(dto);

      expect(result).toEqual({
        verified: false,
        message: 'Registration verification failed',
      });
      expect(service.verifyRegistration).toHaveBeenCalledWith(userId, mockRegistrationResponse, undefined);
    });

    it('should throw NotFoundException when user not found', async () => {
      const userId = 999;
      const dto: FinishRegistrationDto = {
        userId,
        response: mockRegistrationResponse,
      };

      mockWebAuthnService.verifyRegistration.mockRejectedValue(
        new NotFoundException('User not found')
      );

      await expect(controller.finishRegistration(dto)).rejects.toThrow(NotFoundException);
      expect(service.verifyRegistration).toHaveBeenCalledWith(userId, mockRegistrationResponse, undefined);
    });

    it('should throw BadRequestException for WebAuthn registration errors', async () => {
      const userId = 1;
      const dto: FinishRegistrationDto = {
        userId,
        response: mockRegistrationResponse,
      };

      mockWebAuthnService.verifyRegistration.mockRejectedValue(
        new WebAuthnRegistrationError('Invalid registration response')
      );

      await expect(controller.finishRegistration(dto)).rejects.toThrow(BadRequestException);
      expect(service.verifyRegistration).toHaveBeenCalledWith(userId, mockRegistrationResponse, undefined);
    });

    it('should throw InternalServerErrorException for other errors', async () => {
      const userId = 1;
      const dto: FinishRegistrationDto = {
        userId,
        response: mockRegistrationResponse,
      };

      mockWebAuthnService.verifyRegistration.mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(controller.finishRegistration(dto)).rejects.toThrow(InternalServerErrorException);
      expect(service.verifyRegistration).toHaveBeenCalledWith(userId, mockRegistrationResponse, undefined);
    });
  });

  describe('beginAuthentication', () => {
    it('should return authentication options successfully', async () => {
      const userHandle = 'dGVzdA';
      const mockOptions: PublicKeyCredentialRequestOptionsJSON = {
        challenge: 'test-challenge',
        timeout: 60000,
        rpId: 'localhost',
        allowCredentials: [
          {
            id: 'test-credential-id',
            type: 'public-key',
            transports: ['usb', 'nfc'],
          },
        ],
        userVerification: 'preferred',
      };

      mockWebAuthnService.generateAuthenticationOptions.mockResolvedValue(mockOptions);

      const dto: BeginAuthenticationDto = { userHandle };
      const result = await controller.beginAuthentication(dto);

      expect(result).toEqual({ options: mockOptions });
      expect(service.generateAuthenticationOptions).toHaveBeenCalledWith(userHandle);
    });

    it('should return authentication options without userHandle', async () => {
      const mockOptions: PublicKeyCredentialRequestOptionsJSON = {
        challenge: 'test-challenge',
        timeout: 60000,
        rpId: 'localhost',
        userVerification: 'preferred',
      };

      mockWebAuthnService.generateAuthenticationOptions.mockResolvedValue(mockOptions);

      const dto: BeginAuthenticationDto = {};
      const result = await controller.beginAuthentication(dto);

      expect(result).toEqual({ options: mockOptions });
      expect(service.generateAuthenticationOptions).toHaveBeenCalledWith(undefined);
    });

    it('should throw InternalServerErrorException for errors', async () => {
      const dto: BeginAuthenticationDto = {};

      mockWebAuthnService.generateAuthenticationOptions.mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(controller.beginAuthentication(dto)).rejects.toThrow(InternalServerErrorException);
      expect(service.generateAuthenticationOptions).toHaveBeenCalledWith(undefined);
    });
  });

  describe('finishAuthentication', () => {
    const mockAuthenticationResponse: AuthenticationResponseJSON = {
      id: 'test-credential-id',
      rawId: 'test-credential-id',
      response: {
        clientDataJSON: 'test-client-data',
        authenticatorData: 'test-authenticator-data',
        signature: 'test-signature',
        userHandle: 'dGVzdA',
      },
      type: 'public-key',
      clientExtensionResults: {},
    };

    const mockUser = {
      id: 1,
      email: 'test@example.com',
      nombre_usuario: 'Test User',
    };

    it('should return successful authentication result with JWT token', async () => {
      const expectedChallenge = 'test-challenge';
      const mockToken = 'jwt-token-123';

      mockWebAuthnService.verifyAuthentication.mockResolvedValue({
        verified: true,
        user: mockUser,
      });

      mockAuthService.login.mockResolvedValue({
        access_token: mockToken,
      });

      const dto: FinishAuthenticationDto = {
        response: mockAuthenticationResponse,
        expectedChallenge,
      };

      const result = await controller.finishAuthentication(dto);

      expect(result).toEqual({
        verified: true,
        token: mockToken,
        user: {
          id: mockUser.id,
          email: mockUser.email,
          nombre_usuario: mockUser.nombre_usuario,
        },
        message: 'Authentication successful',
      });
      expect(service.verifyAuthentication).toHaveBeenCalledWith(mockAuthenticationResponse, expectedChallenge);
      expect(authService.login).toHaveBeenCalledWith(mockUser);
    });

    it('should authenticate without expectedChallenge', async () => {
      const mockToken = 'jwt-token-123';

      mockWebAuthnService.verifyAuthentication.mockResolvedValue({
        verified: true,
        user: mockUser,
      });

      mockAuthService.login.mockResolvedValue({
        access_token: mockToken,
      });

      const dto: FinishAuthenticationDto = {
        response: mockAuthenticationResponse,
      };

      const result = await controller.finishAuthentication(dto);

      expect(result).toEqual({
        verified: true,
        token: mockToken,
        user: {
          id: mockUser.id,
          email: mockUser.email,
          nombre_usuario: mockUser.nombre_usuario,
        },
        message: 'Authentication successful',
      });
      expect(service.verifyAuthentication).toHaveBeenCalledWith(mockAuthenticationResponse, undefined);
      expect(authService.login).toHaveBeenCalledWith(mockUser);
    });

    it('should throw UnauthorizedException when verification fails', async () => {
      mockWebAuthnService.verifyAuthentication.mockResolvedValue({
        verified: false,
      });

      const dto: FinishAuthenticationDto = {
        response: mockAuthenticationResponse,
      };

      await expect(controller.finishAuthentication(dto)).rejects.toThrow(UnauthorizedException);
      expect(service.verifyAuthentication).toHaveBeenCalledWith(mockAuthenticationResponse, undefined);
      expect(authService.login).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException for WebAuthn authentication errors', async () => {
      const dto: FinishAuthenticationDto = {
        response: mockAuthenticationResponse,
      };

      mockWebAuthnService.verifyAuthentication.mockRejectedValue(
        new WebAuthnAuthenticationError('Invalid authentication response')
      );

      await expect(controller.finishAuthentication(dto)).rejects.toThrow(UnauthorizedException);
      expect(service.verifyAuthentication).toHaveBeenCalledWith(mockAuthenticationResponse, undefined);
      expect(authService.login).not.toHaveBeenCalled();
    });

    it('should throw InternalServerErrorException for other errors', async () => {
      const dto: FinishAuthenticationDto = {
        response: mockAuthenticationResponse,
      };

      mockWebAuthnService.verifyAuthentication.mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(controller.finishAuthentication(dto)).rejects.toThrow(InternalServerErrorException);
      expect(service.verifyAuthentication).toHaveBeenCalledWith(mockAuthenticationResponse, undefined);
      expect(authService.login).not.toHaveBeenCalled();
    });
  });

  describe('getUserCredentials', () => {
    const mockRequest = {
      user: { userId: 1 },
    };

    const mockCredentials = [
      {
        id: 1,
        credentialID: 'credential-1',
        deviceName: 'iPhone',
        credentialDeviceType: 'singleDevice' as const,
        credentialBackedUp: false,
        createdAt: new Date('2023-01-01'),
        lastUsed: new Date('2023-01-02'),
        transports: '["internal"]',
      },
      {
        id: 2,
        credentialID: 'credential-2',
        deviceName: 'Security Key',
        credentialDeviceType: 'multiDevice' as const,
        credentialBackedUp: true,
        createdAt: new Date('2023-01-03'),
        lastUsed: new Date('2023-01-04'),
        transports: '["usb", "nfc"]',
      },
    ];

    it('should return user credentials successfully', async () => {
      mockWebAuthnService.getUserCredentials.mockResolvedValue(mockCredentials);

      const result = await controller.getUserCredentials(mockRequest);

      expect(result).toEqual({
        credentials: [
          {
            id: 1,
            credentialID: 'credential-1',
            deviceName: 'iPhone',
            credentialDeviceType: 'singleDevice',
            credentialBackedUp: false,
            createdAt: new Date('2023-01-01'),
            lastUsed: new Date('2023-01-02'),
            transports: ['internal'],
          },
          {
            id: 2,
            credentialID: 'credential-2',
            deviceName: 'Security Key',
            credentialDeviceType: 'multiDevice',
            credentialBackedUp: true,
            createdAt: new Date('2023-01-03'),
            lastUsed: new Date('2023-01-04'),
            transports: ['usb', 'nfc'],
          },
        ],
        count: 2,
      });
      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
    });

    it('should return empty credentials list', async () => {
      mockWebAuthnService.getUserCredentials.mockResolvedValue([]);

      const result = await controller.getUserCredentials(mockRequest);

      expect(result).toEqual({
        credentials: [],
        count: 0,
      });
      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
    });

    it('should handle credentials without transports', async () => {
      const credentialsWithoutTransports = [
        {
          id: 1,
          credentialID: 'credential-1',
          deviceName: 'iPhone',
          credentialDeviceType: 'singleDevice' as const,
          credentialBackedUp: false,
          createdAt: new Date('2023-01-01'),
          lastUsed: new Date('2023-01-02'),
          transports: null,
        },
      ];

      mockWebAuthnService.getUserCredentials.mockResolvedValue(credentialsWithoutTransports);

      const result = await controller.getUserCredentials(mockRequest);

      expect(result).toEqual({
        credentials: [
          {
            id: 1,
            credentialID: 'credential-1',
            deviceName: 'iPhone',
            credentialDeviceType: 'singleDevice',
            credentialBackedUp: false,
            createdAt: new Date('2023-01-01'),
            lastUsed: new Date('2023-01-02'),
            transports: undefined,
          },
        ],
        count: 1,
      });
      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
    });

    it('should throw InternalServerErrorException for service errors', async () => {
      mockWebAuthnService.getUserCredentials.mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(controller.getUserCredentials(mockRequest)).rejects.toThrow(InternalServerErrorException);
      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
    });
  });

  describe('deleteCredential', () => {
    const mockRequest = {
      user: { userId: 1 },
    };

    const mockUserCredentials = [
      {
        id: 1,
        credentialID: 'credential-1',
        deviceName: 'iPhone',
        userId: 1,
      },
      {
        id: 2,
        credentialID: 'credential-2',
        deviceName: 'Security Key',
        userId: 1,
      },
    ];

    it('should delete credential successfully', async () => {
      const credentialId = 'credential-1';
      
      mockWebAuthnService.getUserCredentials.mockResolvedValue(mockUserCredentials);
      mockWebAuthnService.deleteCredential.mockResolvedValue(true);

      await controller.deleteCredential(mockRequest, credentialId);

      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
      expect(service.deleteCredential).toHaveBeenCalledWith(1, credentialId);
    });

    it('should throw BadRequestException for empty credential ID', async () => {
      const credentialId = '';

      await expect(controller.deleteCredential(mockRequest, credentialId)).rejects.toThrow(BadRequestException);
      expect(service.getUserCredentials).not.toHaveBeenCalled();
      expect(service.deleteCredential).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException for whitespace-only credential ID', async () => {
      const credentialId = '   ';

      await expect(controller.deleteCredential(mockRequest, credentialId)).rejects.toThrow(BadRequestException);
      expect(service.getUserCredentials).not.toHaveBeenCalled();
      expect(service.deleteCredential).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException when credential does not belong to user', async () => {
      const credentialId = 'credential-not-owned';
      
      mockWebAuthnService.getUserCredentials.mockResolvedValue(mockUserCredentials);

      await expect(controller.deleteCredential(mockRequest, credentialId)).rejects.toThrow(NotFoundException);
      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
      expect(service.deleteCredential).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException when credential not found in database', async () => {
      const credentialId = 'credential-1';
      
      mockWebAuthnService.getUserCredentials.mockResolvedValue(mockUserCredentials);
      mockWebAuthnService.deleteCredential.mockResolvedValue(false);

      await expect(controller.deleteCredential(mockRequest, credentialId)).rejects.toThrow(NotFoundException);
      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
      expect(service.deleteCredential).toHaveBeenCalledWith(1, credentialId);
    });

    it('should throw InternalServerErrorException for service errors', async () => {
      const credentialId = 'credential-1';
      
      mockWebAuthnService.getUserCredentials.mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(controller.deleteCredential(mockRequest, credentialId)).rejects.toThrow(InternalServerErrorException);
      expect(service.getUserCredentials).toHaveBeenCalledWith(1);
      expect(service.deleteCredential).not.toHaveBeenCalled();
    });
  });
});