import { validate } from 'class-validator';
import { plainToClass } from 'class-transformer';
import {
  BeginRegistrationDto,
  FinishRegistrationDto,
  BeginAuthenticationDto,
  FinishAuthenticationDto,
  DeleteCredentialDto,
} from './index';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';

describe('WebAuthn DTOs', () => {
  describe('BeginRegistrationDto', () => {
    it('should validate valid input', async () => {
      const dto = plainToClass(BeginRegistrationDto, {
        userId: 1,
        deviceName: 'My Device',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should validate without optional deviceName', async () => {
      const dto = plainToClass(BeginRegistrationDto, {
        userId: 1,
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should fail validation with invalid userId', async () => {
      const dto = plainToClass(BeginRegistrationDto, {
        userId: 'invalid',
        deviceName: 'My Device',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('userId');
    });

    it('should fail validation with empty deviceName', async () => {
      const dto = plainToClass(BeginRegistrationDto, {
        userId: 1,
        deviceName: '',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('deviceName');
    });

    it('should fail validation with too long deviceName', async () => {
      const dto = plainToClass(BeginRegistrationDto, {
        userId: 1,
        deviceName: 'a'.repeat(101),
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('deviceName');
    });
  });

  describe('FinishRegistrationDto', () => {
    const validRegistrationResponse: RegistrationResponseJSON = {
      id: 'test-credential-id',
      rawId: 'test-raw-id',
      type: 'public-key',
      response: {
        clientDataJSON: 'test-client-data',
        attestationObject: 'test-attestation-object',
        transports: ['usb', 'nfc'],
      },
      clientExtensionResults: {},
    };

    it('should validate valid input', async () => {
      const dto = plainToClass(FinishRegistrationDto, {
        userId: 1,
        response: validRegistrationResponse,
        deviceName: 'My Device',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should validate without optional deviceName', async () => {
      const dto = plainToClass(FinishRegistrationDto, {
        userId: 1,
        response: validRegistrationResponse,
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should fail validation with invalid response', async () => {
      const dto = plainToClass(FinishRegistrationDto, {
        userId: 1,
        response: { invalid: 'response' },
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('response');
    });
  });

  describe('BeginAuthenticationDto', () => {
    it('should validate valid input', async () => {
      const dto = plainToClass(BeginAuthenticationDto, {
        userHandle: 'test-user-handle',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should validate without optional userHandle', async () => {
      const dto = plainToClass(BeginAuthenticationDto, {});

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should fail validation with non-string userHandle', async () => {
      const dto = plainToClass(BeginAuthenticationDto, {
        userHandle: 123,
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('userHandle');
    });
  });

  describe('FinishAuthenticationDto', () => {
    const validAuthenticationResponse: AuthenticationResponseJSON = {
      id: 'test-credential-id',
      rawId: 'test-raw-id',
      type: 'public-key',
      response: {
        clientDataJSON: 'test-client-data',
        authenticatorData: 'test-authenticator-data',
        signature: 'test-signature',
        userHandle: 'test-user-handle',
      },
      clientExtensionResults: {},
    };

    it('should validate valid input', async () => {
      const dto = plainToClass(FinishAuthenticationDto, {
        response: validAuthenticationResponse,
        expectedChallenge: 'test-challenge',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should validate without optional expectedChallenge', async () => {
      const dto = plainToClass(FinishAuthenticationDto, {
        response: validAuthenticationResponse,
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should fail validation with invalid response', async () => {
      const dto = plainToClass(FinishAuthenticationDto, {
        response: { invalid: 'response' },
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('response');
    });
  });

  describe('DeleteCredentialDto', () => {
    it('should validate valid input', async () => {
      const dto = plainToClass(DeleteCredentialDto, {
        credentialId: 'test-credential-id',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(0);
    });

    it('should fail validation with empty credentialId', async () => {
      const dto = plainToClass(DeleteCredentialDto, {
        credentialId: '',
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('credentialId');
    });

    it('should fail validation with non-string credentialId', async () => {
      const dto = plainToClass(DeleteCredentialDto, {
        credentialId: 123,
      });

      const errors = await validate(dto);
      expect(errors).toHaveLength(1);
      expect(errors[0].property).toBe('credentialId');
    });
  });
});