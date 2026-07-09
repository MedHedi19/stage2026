import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(private readonly configService: ConfigService) {
    const jwtSecret = configService.get<string>('JWT_SECRET');
    if (!jwtSecret || jwtSecret === 'super_secret_signing_key_change_me_in_prod' || jwtSecret === 'default_jwt_secret_key_123') {
      throw new Error('JWT_SECRET must be set to a strong, unique value in production environment variables');
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  async validate(payload: any) {
    if (payload.mfaRequired) {
      throw new UnauthorizedException('MFA verification required');
    }
    return {
      id: payload.sub,
      username: payload.username,
      role: payload.role,
      mfaEnabled: payload.mfaEnabled,
    };
  }
}
