import { WebAuthnCredential } from './webauthn-credential.entity';
import { User } from '../user/user.entity';

describe('WebAuthnCredential Entity', () => {
  it('should create a WebAuthnCredential instance', () => {
    const user = new User();
    user.id = 1;
    user.email = 'test@example.com';
    user.nombre_usuario = 'testuser';
    user.password = 'hashedpassword';

    const credential = new WebAuthnCredential();
    credential.id = 1;
    credential.credentialID = 'test-credential-id';
    credential.credentialPublicKey = 'test-public-key';
    credential.counter = 0;
    credential.credentialDeviceType = 'singleDevice';
    credential.credentialBackedUp = false;
    credential.transports = JSON.stringify(['usb', 'nfc']);
    credential.deviceName = 'Test Device';
    credential.user = user;
    credential.userId = user.id;
    credential.createdAt = new Date();
    credential.lastUsed = new Date();

    expect(credential).toBeDefined();
    expect(credential.credentialID).toBe('test-credential-id');
    expect(credential.credentialPublicKey).toBe('test-public-key');
    expect(credential.counter).toBe(0);
    expect(credential.credentialDeviceType).toBe('singleDevice');
    expect(credential.credentialBackedUp).toBe(false);
    expect(credential.transports).toBe(JSON.stringify(['usb', 'nfc']));
    expect(credential.deviceName).toBe('Test Device');
    expect(credential.user).toBe(user);
    expect(credential.userId).toBe(1);
  });

  it('should have proper default values', () => {
    const credential = new WebAuthnCredential();
    
    // These should be set by TypeORM decorators when saved to database
    expect(credential.counter).toBeUndefined(); // Will be set to 0 by default in database
    expect(credential.credentialBackedUp).toBeUndefined(); // Will be set to false by default in database
  });

  it('should support optional fields', () => {
    const credential = new WebAuthnCredential();
    credential.credentialID = 'test-id';
    credential.credentialPublicKey = 'test-key';
    credential.credentialDeviceType = 'multiDevice';
    credential.userId = 1;

    // Optional fields should be undefined if not set
    expect(credential.transports).toBeUndefined();
    expect(credential.deviceName).toBeUndefined();
  });
});