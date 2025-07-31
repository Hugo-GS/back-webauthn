import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';

@ValidatorConstraint({ name: 'isWebAuthnRegistrationResponse', async: false })
export class IsWebAuthnRegistrationResponseConstraint implements ValidatorConstraintInterface {
  validate(value: any, args: ValidationArguments) {
    if (!value || typeof value !== 'object') {
      return false;
    }

    const response = value as RegistrationResponseJSON;

    // Check required properties for WebAuthn registration response
    return (
      typeof response.id === 'string' &&
      typeof response.rawId === 'string' &&
      typeof response.type === 'string' &&
      response.type === 'public-key' &&
      response.response &&
      typeof response.response === 'object' &&
      typeof response.response.clientDataJSON === 'string' &&
      typeof response.response.attestationObject === 'string'
    );
  }

  defaultMessage(args: ValidationArguments) {
    return 'Invalid WebAuthn registration response format';
  }
}

@ValidatorConstraint({ name: 'isWebAuthnAuthenticationResponse', async: false })
export class IsWebAuthnAuthenticationResponseConstraint implements ValidatorConstraintInterface {
  validate(value: any, args: ValidationArguments) {
    if (!value || typeof value !== 'object') {
      return false;
    }

    const response = value as AuthenticationResponseJSON;

    // Check required properties for WebAuthn authentication response
    return (
      typeof response.id === 'string' &&
      typeof response.rawId === 'string' &&
      typeof response.type === 'string' &&
      response.type === 'public-key' &&
      response.response &&
      typeof response.response === 'object' &&
      typeof response.response.clientDataJSON === 'string' &&
      typeof response.response.authenticatorData === 'string' &&
      typeof response.response.signature === 'string'
    );
  }

  defaultMessage(args: ValidationArguments) {
    return 'Invalid WebAuthn authentication response format';
  }
}

@ValidatorConstraint({ name: 'isBase64URL', async: false })
export class IsBase64URLConstraint implements ValidatorConstraintInterface {
  validate(value: any, args: ValidationArguments) {
    if (typeof value !== 'string') {
      return false;
    }

    // Base64URL pattern: only contains A-Z, a-z, 0-9, -, _ and no padding
    const base64URLPattern = /^[A-Za-z0-9_-]+$/;
    return base64URLPattern.test(value);
  }

  defaultMessage(args: ValidationArguments) {
    return 'Value must be a valid Base64URL string';
  }
}

// Custom decorators
export function IsWebAuthnRegistrationResponse(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsWebAuthnRegistrationResponseConstraint,
    });
  };
}

export function IsWebAuthnAuthenticationResponse(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsWebAuthnAuthenticationResponseConstraint,
    });
  };
}

export function IsBase64URL(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsBase64URLConstraint,
    });
  };
}