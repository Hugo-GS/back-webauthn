import { randomBytes } from 'crypto';

/**
 * Utility functions for WebAuthn operations
 */
export class WebAuthnUtils {
  /**
   * Generate a cryptographically secure random challenge
   * @param length - Length of the challenge in bytes (default: 32)
   * @returns Base64URL encoded challenge string
   */
  static generateChallenge(length: number = 32): string {
    const challenge = randomBytes(length);
    return this.bufferToBase64URL(challenge);
  }

  /**
   * Convert a Buffer to Base64URL encoded string
   * @param buffer - Buffer to encode
   * @returns Base64URL encoded string
   */
  static bufferToBase64URL(buffer: Buffer): string {
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Convert a Base64URL encoded string to Buffer
   * @param base64url - Base64URL encoded string
   * @returns Decoded Buffer
   */
  static base64URLToBuffer(base64url: string): Buffer {
    // Add padding if necessary
    const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
    const base64 = base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/') + padding;
    
    return Buffer.from(base64, 'base64');
  }

  /**
   * Convert a Uint8Array to Base64URL encoded string
   * @param uint8Array - Uint8Array to encode
   * @returns Base64URL encoded string
   */
  static uint8ArrayToBase64URL(uint8Array: Uint8Array): string {
    return this.bufferToBase64URL(Buffer.from(uint8Array));
  }

  /**
   * Convert a Base64URL encoded string to Uint8Array
   * @param base64url - Base64URL encoded string
   * @returns Decoded Uint8Array
   */
  static base64URLToUint8Array(base64url: string): Uint8Array {
    const buffer = this.base64URLToBuffer(base64url);
    return new Uint8Array(buffer);
  }

  /**
   * Generate a random user handle for WebAuthn
   * @param length - Length of the user handle in bytes (default: 32)
   * @returns Buffer containing the user handle
   */
  static generateUserHandle(length: number = 32): Buffer {
    return randomBytes(length);
  }

  /**
   * Validate that a string is a valid Base64URL encoded string
   * @param str - String to validate
   * @returns True if valid Base64URL, false otherwise
   */
  static isValidBase64URL(str: string): boolean {
    // Base64URL should only contain A-Z, a-z, 0-9, -, _
    const base64URLRegex = /^[A-Za-z0-9_-]+$/;
    return base64URLRegex.test(str);
  }

  /**
   * Convert a string to Base64URL encoded string
   * @param str - String to encode
   * @returns Base64URL encoded string
   */
  static stringToBase64URL(str: string): string {
    const buffer = Buffer.from(str, 'utf8');
    return this.bufferToBase64URL(buffer);
  }

  /**
   * Convert a Base64URL encoded string to string
   * @param base64url - Base64URL encoded string
   * @returns Decoded string
   */
  static base64URLToString(base64url: string): string {
    const buffer = this.base64URLToBuffer(base64url);
    return buffer.toString('utf8');
  }

  /**
   * Generate a secure random string for various WebAuthn purposes
   * @param length - Length in bytes (default: 16)
   * @returns Base64URL encoded random string
   */
  static generateRandomString(length: number = 16): string {
    return this.bufferToBase64URL(randomBytes(length));
  }
}