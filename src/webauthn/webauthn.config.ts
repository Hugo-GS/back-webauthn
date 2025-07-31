import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface WebAuthnConfig {
  rpName: string;
  rpID: string;
  origin: string;
  timeout: number;
  requireResidentKey: boolean;
  userVerification: 'required' | 'preferred' | 'discouraged';
}

@Injectable()
export class WebAuthnConfigService {
  private readonly config: WebAuthnConfig;

  constructor(private configService: ConfigService) {
    this.config = {
      rpName: this.configService.get<string>('WEBAUTHN_RP_NAME', 'WebAuthn Demo'),
      rpID: this.configService.get<string>('WEBAUTHN_RP_ID', 'localhost'),
      origin: this.buildOrigin(),
      timeout: parseInt(this.configService.get<string>('WEBAUTHN_TIMEOUT', '60000')),
      requireResidentKey: this.configService.get<string>('WEBAUTHN_REQUIRE_RESIDENT_KEY') === 'true',
      userVerification: this.configService.get<'required' | 'preferred' | 'discouraged'>(
        'WEBAUTHN_USER_VERIFICATION',
        'preferred'
      ),
    };
  }

  getConfig(): WebAuthnConfig {
    return { ...this.config };
  }

  getRpName(): string {
    return this.config.rpName;
  }

  getRpID(): string {
    return this.config.rpID;
  }

  getOrigin(): string {
    return this.config.origin;
  }

  getTimeout(): number {
    return this.config.timeout;
  }

  getRequireResidentKey(): boolean {
    return this.config.requireResidentKey;
  }

  getUserVerification(): 'required' | 'preferred' | 'discouraged' {
    return this.config.userVerification;
  }

  private buildOrigin(): string {
    // First check if WEBAUTHN_ORIGIN is explicitly set
    const explicitOrigin = this.configService.get<string>('WEBAUTHN_ORIGIN');
    if (explicitOrigin) {
      console.log('🔧 [WebAuthn Config] Using explicit WEBAUTHN_ORIGIN:', {
        explicitOrigin
      });
      return explicitOrigin;
    }

    const allowedOrigins = this.configService.get<string>('ALLOWED_ORIGINS', '*');
    
    console.log('🔧 [WebAuthn Config] Building origin from ALLOWED_ORIGINS:', {
      allowedOrigins,
      isWildcard: !allowedOrigins || allowedOrigins === '*'
    });
    
    // If ALLOWED_ORIGINS is *, construct origin from RP_ID and port
    if (!allowedOrigins || allowedOrigins === '*') {
      const rpID = this.configService.get<string>('WEBAUTHN_RP_ID', 'localhost');
      const port = this.configService.get<string>('PORT', '3000');
      
      // Check if rpID already includes protocol and port
      if (rpID && rpID.includes('://')) {
        return rpID;
      }
      
      // For localhost, use http, otherwise use https
      const safeRpID = rpID || 'localhost';
      const protocol = safeRpID === 'localhost' || safeRpID.startsWith('127.') ? 'http' : 'https';
      const portSuffix = (protocol === 'http' && port !== '80') || (protocol === 'https' && port !== '443') 
        ? `:${port}` 
        : '';
      
      const constructedOrigin = `${protocol}://${safeRpID}${portSuffix}`;
      console.log('🔧 [WebAuthn Config] Constructed origin from RP_ID:', {
        rpID,
        port,
        protocol,
        portSuffix,
        constructedOrigin
      });
      return constructedOrigin;
    }
    
    // Return the first allowed origin if multiple are specified
    const finalOrigin = allowedOrigins.split(',')[0].trim();
    console.log('🔧 [WebAuthn Config] Using configured origin:', {
      allowedOrigins,
      finalOrigin
    });
    return finalOrigin;
  }
}