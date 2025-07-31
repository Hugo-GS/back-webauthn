import { WebAuthnUtils } from './webauthn.utils';

describe('WebAuthnUtils', () => {
  describe('generateChallenge', () => {
    it('should generate a challenge with default length', () => {
      const challenge = WebAuthnUtils.generateChallenge();
      expect(typeof challenge).toBe('string');
      expect(challenge.length).toBeGreaterThan(0);
      expect(WebAuthnUtils.isValidBase64URL(challenge)).toBe(true);
    });

    it('should generate a challenge with custom length', () => {
      const challenge = WebAuthnUtils.generateChallenge(16);
      expect(typeof challenge).toBe('string');
      expect(challenge.length).toBeGreaterThan(0);
      expect(WebAuthnUtils.isValidBase64URL(challenge)).toBe(true);
    });

    it('should generate different challenges on each call', () => {
      const challenge1 = WebAuthnUtils.generateChallenge();
      const challenge2 = WebAuthnUtils.generateChallenge();
      expect(challenge1).not.toBe(challenge2);
    });
  });

  describe('Base64URL encoding/decoding', () => {
    const testBuffer = Buffer.from('Hello, World!', 'utf8');
    const expectedBase64URL = 'SGVsbG8sIFdvcmxkIQ';

    it('should encode Buffer to Base64URL', () => {
      const encoded = WebAuthnUtils.bufferToBase64URL(testBuffer);
      expect(encoded).toBe(expectedBase64URL);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });

    it('should decode Base64URL to Buffer', () => {
      const decoded = WebAuthnUtils.base64URLToBuffer(expectedBase64URL);
      expect(decoded).toEqual(testBuffer);
    });

    it('should handle round-trip encoding/decoding', () => {
      const original = Buffer.from('Test data with special chars: +/=', 'utf8');
      const encoded = WebAuthnUtils.bufferToBase64URL(original);
      const decoded = WebAuthnUtils.base64URLToBuffer(encoded);
      expect(decoded).toEqual(original);
    });
  });

  describe('Uint8Array encoding/decoding', () => {
    const testArray = new Uint8Array([72, 101, 108, 108, 111]);
    const expectedBase64URL = 'SGVsbG8';

    it('should encode Uint8Array to Base64URL', () => {
      const encoded = WebAuthnUtils.uint8ArrayToBase64URL(testArray);
      expect(encoded).toBe(expectedBase64URL);
    });

    it('should decode Base64URL to Uint8Array', () => {
      const decoded = WebAuthnUtils.base64URLToUint8Array(expectedBase64URL);
      expect(decoded).toEqual(testArray);
    });

    it('should handle round-trip encoding/decoding', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
      const encoded = WebAuthnUtils.uint8ArrayToBase64URL(original);
      const decoded = WebAuthnUtils.base64URLToUint8Array(encoded);
      expect(decoded).toEqual(original);
    });
  });

  describe('String encoding/decoding', () => {
    const testString = 'Hello, WebAuthn!';
    
    it('should encode string to Base64URL', () => {
      const encoded = WebAuthnUtils.stringToBase64URL(testString);
      expect(typeof encoded).toBe('string');
      expect(WebAuthnUtils.isValidBase64URL(encoded)).toBe(true);
    });

    it('should decode Base64URL to string', () => {
      const encoded = WebAuthnUtils.stringToBase64URL(testString);
      const decoded = WebAuthnUtils.base64URLToString(encoded);
      expect(decoded).toBe(testString);
    });

    it('should handle UTF-8 characters', () => {
      const unicodeString = 'Hello 🌍 WebAuthn! 🔐';
      const encoded = WebAuthnUtils.stringToBase64URL(unicodeString);
      const decoded = WebAuthnUtils.base64URLToString(encoded);
      expect(decoded).toBe(unicodeString);
    });
  });

  describe('generateUserHandle', () => {
    it('should generate a user handle with default length', () => {
      const userHandle = WebAuthnUtils.generateUserHandle();
      expect(Buffer.isBuffer(userHandle)).toBe(true);
      expect(userHandle.length).toBe(32);
    });

    it('should generate a user handle with custom length', () => {
      const userHandle = WebAuthnUtils.generateUserHandle(16);
      expect(Buffer.isBuffer(userHandle)).toBe(true);
      expect(userHandle.length).toBe(16);
    });

    it('should generate different user handles on each call', () => {
      const handle1 = WebAuthnUtils.generateUserHandle();
      const handle2 = WebAuthnUtils.generateUserHandle();
      expect(handle1).not.toEqual(handle2);
    });
  });

  describe('isValidBase64URL', () => {
    it('should return true for valid Base64URL strings', () => {
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8')).toBe(true);
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8tV29ybGQ')).toBe(true);
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8_V29ybGQ')).toBe(true);
      expect(WebAuthnUtils.isValidBase64URL('123456789')).toBe(true);
      expect(WebAuthnUtils.isValidBase64URL('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')).toBe(true);
    });

    it('should return false for invalid Base64URL strings', () => {
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8+')).toBe(false); // contains +
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8/')).toBe(false); // contains /
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8=')).toBe(false); // contains =
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8 ')).toBe(false); // contains space
      expect(WebAuthnUtils.isValidBase64URL('SGVsbG8!')).toBe(false); // contains !
      expect(WebAuthnUtils.isValidBase64URL('')).toBe(false); // empty string
    });
  });

  describe('generateRandomString', () => {
    it('should generate a random string with default length', () => {
      const randomString = WebAuthnUtils.generateRandomString();
      expect(typeof randomString).toBe('string');
      expect(randomString.length).toBeGreaterThan(0);
      expect(WebAuthnUtils.isValidBase64URL(randomString)).toBe(true);
    });

    it('should generate a random string with custom length', () => {
      const randomString = WebAuthnUtils.generateRandomString(8);
      expect(typeof randomString).toBe('string');
      expect(randomString.length).toBeGreaterThan(0);
      expect(WebAuthnUtils.isValidBase64URL(randomString)).toBe(true);
    });

    it('should generate different strings on each call', () => {
      const string1 = WebAuthnUtils.generateRandomString();
      const string2 = WebAuthnUtils.generateRandomString();
      expect(string1).not.toBe(string2);
    });
  });

  describe('edge cases', () => {
    it('should handle empty buffer encoding', () => {
      const emptyBuffer = Buffer.alloc(0);
      const encoded = WebAuthnUtils.bufferToBase64URL(emptyBuffer);
      expect(encoded).toBe('');
      
      const decoded = WebAuthnUtils.base64URLToBuffer(encoded);
      expect(decoded).toEqual(emptyBuffer);
    });

    it('should handle single byte buffer', () => {
      const singleByte = Buffer.from([65]); // 'A'
      const encoded = WebAuthnUtils.bufferToBase64URL(singleByte);
      const decoded = WebAuthnUtils.base64URLToBuffer(encoded);
      expect(decoded).toEqual(singleByte);
    });

    it('should handle padding correctly', () => {
      // Test different padding scenarios
      const testCases = [
        Buffer.from('A'),      // 1 byte - needs 2 padding chars
        Buffer.from('AB'),     // 2 bytes - needs 1 padding char  
        Buffer.from('ABC'),    // 3 bytes - needs no padding
        Buffer.from('ABCD'),   // 4 bytes - needs 2 padding chars
      ];

      testCases.forEach(buffer => {
        const encoded = WebAuthnUtils.bufferToBase64URL(buffer);
        const decoded = WebAuthnUtils.base64URLToBuffer(encoded);
        expect(decoded).toEqual(buffer);
      });
    });
  });
});