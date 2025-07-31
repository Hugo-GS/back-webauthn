import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { WebAuthnConfigService } from './webauthn.config';

describe('WebAuthnConfigService', () => {
  let service: WebAuthnConfigService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WebAuthnConfigService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<WebAuthnConfigService>(WebAuthnConfigService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('constructor', () => {
    it('should initialize with default values when env vars are not set', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string, defaultValue?: any) => {
        const defaults = {
          WEBAUTHN_RP_NAME: 'WebAuthn Demo',
          WEBAUTHN_RP_ID: 'localhost',
          ALLOWED_ORIGINS: '*',
          PORT: '3000',
          WEBAUTHN_TIMEOUT: '60000',
          WEBAUTHN_REQUIRE_RESIDENT_KEY: undefined,
          WEBAUTHN_USER_VERIFICATION: 'preferred',
        };
        return defaults[key] || defaultValue;
      });

      const newService = new WebAuthnConfigService(configService);
      const config = newService.getConfig();

      expect(config.rpName).toBe('WebAuthn Demo');
      expect(config.rpID).toBe('localhost');
      expect(config.origin).toBe('http://localhost:3000');
      expect(config.timeout).toBe(60000);
      expect(config.requireResidentKey).toBe(false);
      expect(config.userVerification).toBe('preferred');
    });

    it('should use environment variables when provided', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string, defaultValue?: any) => {
        const envVars = {
          WEBAUTHN_RP_NAME: 'Test App',
          WEBAUTHN_RP_ID: 'example.com',
          ALLOWED_ORIGINS: 'https://example.com',
          PORT: '3000',
          WEBAUTHN_TIMEOUT: '30000',
          WEBAUTHN_REQUIRE_RESIDENT_KEY: 'true',
          WEBAUTHN_USER_VERIFICATION: 'required',
        };
        return envVars[key] || defaultValue;
      });

      const newService = new WebAuthnConfigService(configService);
      const config = newService.getConfig();

      expect(config.rpName).toBe('Test App');
      expect(config.rpID).toBe('example.com');
      expect(config.origin).toBe('https://example.com');
      expect(config.timeout).toBe(30000);
      expect(config.requireResidentKey).toBe(true);
      expect(config.userVerification).toBe('required');
    });
  });

  describe('origin generation', () => {
    it('should construct origin from RP_ID when ALLOWED_ORIGINS is *', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string, defaultValue?: any) => {
        const values = {
          WEBAUTHN_RP_ID: 'localhost',
          ALLOWED_ORIGINS: '*',
          PORT: '3000',
        };
        return values[key] || defaultValue;
      });

      const newService = new WebAuthnConfigService(configService);
      expect(newService.getOrigin()).toBe('http://localhost:3000');
    });

    it('should use https for non-localhost domains', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string, defaultValue?: any) => {
        const values = {
          WEBAUTHN_RP_ID: 'example.com',
          ALLOWED_ORIGINS: '*',
          PORT: '443',
        };
        return values[key] || defaultValue;
      });

      const newService = new WebAuthnConfigService(configService);
      expect(newService.getOrigin()).toBe('https://example.com');
    });

    it('should return RP_ID as-is if it already includes protocol', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string, defaultValue?: any) => {
        const values = {
          WEBAUTHN_RP_ID: 'https://example.com:8080',
          ALLOWED_ORIGINS: '*',
          PORT: '3000',
        };
        return values[key] || defaultValue;
      });

      const newService = new WebAuthnConfigService(configService);
      expect(newService.getOrigin()).toBe('https://example.com:8080');
    });

    it('should use first origin when multiple are specified', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string, defaultValue?: any) => {
        const values = {
          ALLOWED_ORIGINS: 'https://app1.com,https://app2.com',
        };
        return values[key] || defaultValue;
      });

      const newService = new WebAuthnConfigService(configService);
      expect(newService.getOrigin()).toBe('https://app1.com');
    });
  });

  describe('getter methods', () => {
    let testService: WebAuthnConfigService;

    beforeEach(() => {
      const mockConfigService = {
        get: jest.fn().mockImplementation((key: string, defaultValue?: any) => {
          const values = {
            WEBAUTHN_RP_NAME: 'Test App',
            WEBAUTHN_RP_ID: 'test.com',
            ALLOWED_ORIGINS: 'https://test.com',
            PORT: '3000',
            WEBAUTHN_TIMEOUT: '45000',
            WEBAUTHN_REQUIRE_RESIDENT_KEY: 'true',
            WEBAUTHN_USER_VERIFICATION: 'discouraged',
          };
          return values[key] || defaultValue;
        }),
      };
      testService = new WebAuthnConfigService(mockConfigService as any);
    });

    it('should return correct RP name', () => {
      expect(testService.getRpName()).toBe('Test App');
    });

    it('should return correct RP ID', () => {
      expect(testService.getRpID()).toBe('test.com');
    });

    it('should return correct origin', () => {
      expect(testService.getOrigin()).toBe('https://test.com');
    });

    it('should return correct timeout', () => {
      expect(testService.getTimeout()).toBe(45000);
    });

    it('should return correct resident key requirement', () => {
      expect(testService.getRequireResidentKey()).toBe(true);
    });

    it('should return correct user verification', () => {
      expect(testService.getUserVerification()).toBe('discouraged');
    });
  });
});