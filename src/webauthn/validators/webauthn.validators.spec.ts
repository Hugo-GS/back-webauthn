import {
  IsWebAuthnRegistrationResponseConstraint,
  IsWebAuthnAuthenticationResponseConstraint,
  IsBase64URLConstraint,
} from './webauthn.validators';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';

describe('WebAuthn Validators', () => {
  describe('IsWebAuthnRegistrationResponseConstraint', () => {
    const validator = new IsWebAuthnRegistrationResponseConstraint();

    it('should validate valid registration response', () => {
      const validResponse: RegistrationResponseJSON = {
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

      expect(validator.validate(validResponse, {} as any)).toBe(true);
    });

    it('should reject invalid registration response - missing properties', () => {
      const invalidResponse = {
        id: 'test-credential-id',
        // missing rawId, type, response
      };

      expect(validator.validate(invalidResponse, {} as any)).toBe(false);
    });

    it('should reject invalid registration response - wrong type', () => {
      const invalidResponse = {
        id: 'test-credential-id',
        rawId: 'test-raw-id',
        type: 'wrong-type',
        response: {
          clientDataJSON: 'test-client-data',
          attestationObject: 'test-attestation-object',
        },
      };

      expect(validator.validate(invalidResponse, {} as any)).toBe(false);
    });

    it('should reject invalid registration response - missing response properties', () => {
      const invalidResponse = {
        id: 'test-credential-id',
        rawId: 'test-raw-id',
        type: 'public-key',
        response: {
          clientDataJSON: 'test-client-data',
          // missing attestationObject
        },
      };

      expect(validator.validate(invalidResponse, {} as any)).toBe(false);
    });

    it('should reject non-object values', () => {
      expect(validator.validate(null, {} as any)).toBe(false);
      expect(validator.validate(undefined, {} as any)).toBe(false);
      expect(validator.validate('string', {} as any)).toBe(false);
      expect(validator.validate(123, {} as any)).toBe(false);
    });
  });

  describe('IsWebAuthnAuthenticationResponseConstraint', () => {
    const validator = new IsWebAuthnAuthenticationResponseConstraint();

    it('should validate valid authentication response', () => {
      const validResponse: AuthenticationResponseJSON = {
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

      expect(validator.validate(validResponse, {} as any)).toBe(true);
    });

    it('should reject invalid authentication response - missing properties', () => {
      const invalidResponse = {
        id: 'test-credential-id',
        // missing rawId, type, response
      };

      expect(validator.validate(invalidResponse, {} as any)).toBe(false);
    });

    it('should reject invalid authentication response - wrong type', () => {
      const invalidResponse = {
        id: 'test-credential-id',
        rawId: 'test-raw-id',
        type: 'wrong-type',
        response: {
          clientDataJSON: 'test-client-data',
          authenticatorData: 'test-authenticator-data',
          signature: 'test-signature',
        },
      };

      expect(validator.validate(invalidResponse, {} as any)).toBe(false);
    });

    it('should reject invalid authentication response - missing response properties', () => {
      const invalidResponse = {
        id: 'test-credential-id',
        rawId: 'test-raw-id',
        type: 'public-key',
        response: {
          clientDataJSON: 'test-client-data',
          authenticatorData: 'test-authenticator-data',
          // missing signature
        },
      };

      expect(validator.validate(invalidResponse, {} as any)).toBe(false);
    });

    it('should reject non-object values', () => {
      expect(validator.validate(null, {} as any)).toBe(false);
      expect(validator.validate(undefined, {} as any)).toBe(false);
      expect(validator.validate('string', {} as any)).toBe(false);
      expect(validator.validate(123, {} as any)).toBe(false);
    });
  });

  describe('IsBase64URLConstraint', () => {
    const validator = new IsBase64URLConstraint();

    it('should validate valid Base64URL strings', () => {
      expect(validator.validate('SGVsbG9Xb3JsZA', {} as any)).toBe(true);
      expect(validator.validate('SGVsbG9Xb3JsZA-_', {} as any)).toBe(true);
      expect(validator.validate('abcDEF123-_', {} as any)).toBe(true);
    });

    it('should reject invalid Base64URL strings', () => {
      expect(validator.validate('SGVsbG9Xb3JsZA==', {} as any)).toBe(false); // has padding
      expect(validator.validate('SGVsbG9Xb3JsZA+/', {} as any)).toBe(false); // has + and /
      expect(validator.validate('SGVsbG9Xb3JsZA!', {} as any)).toBe(false); // has invalid character
      expect(validator.validate('', {} as any)).toBe(false); // empty string
    });

    it('should reject non-string values', () => {
      expect(validator.validate(null, {} as any)).toBe(false);
      expect(validator.validate(undefined, {} as any)).toBe(false);
      expect(validator.validate(123, {} as any)).toBe(false);
      expect(validator.validate({}, {} as any)).toBe(false);
    });
  });
});