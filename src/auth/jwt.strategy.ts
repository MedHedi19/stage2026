import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET') || 'default_jwt_secret_key_123',
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
