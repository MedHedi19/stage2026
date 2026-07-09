import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findByUsername(username, true);
    if (user && (await bcrypt.compare(pass, user.passwordHash))) {
      const { passwordHash, mfaSecret, ...result } = user;
      return result;
    }
    return null;
  }

  async login(username: string, pass: string) {
    const user = await this.validateUser(username, pass);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.mfaEnabled) {
      const payload = {
        sub: user.id,
        username: user.username,
        role: user.role,
        mfaRequired: true,
      };
      const tempToken = this.jwtService.sign(payload, { expiresIn: '5m' });
      return {
        mfaRequired: true,
        tempToken,
      };
    }

    return {
      mfaRequired: false,
      accessToken: this.generateAccessToken(user),
      user,
    };
  }

  async signup(username: string, password: string) {
    const existingUser = await this.usersService.findByUsername(username);
    if (existingUser) {
      throw new BadRequestException('Username already exists');
    }

    const user = await this.usersService.create(username, password, 'viewer');
    
    return {
      message: 'User created successfully',
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        mfaEnabled: user.mfaEnabled,
      },
    };
  }

  generateAccessToken(user: any): string {
    const payload = {
      username: user.username,
      sub: user.id,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
    };
    return this.jwtService.sign(payload);
  }

  async setupMfa(userId: number) {
    const user = await this.usersService.findOne(userId);
    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(user.username, 'IDS-IPS-Intelligent', secret);

    await this.usersService.update(userId, { mfaSecret: secret });

    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);
    return {
      secret,
      qrCodeDataUrl,
    };
  }

  async verifyMfaSetup(userId: number, code: string) {
    const user = await this.usersService.findByUsername(
      (await this.usersService.findOne(userId)).username,
      true,
    );
    if (!user || !user.mfaSecret) {
      throw new BadRequestException('MFA not set up yet');
    }

    const isValid = authenticator.check(code, user.mfaSecret);

    if (!isValid) {
      throw new UnauthorizedException('Invalid verification code');
    }

    const updatedUser = await this.usersService.update(userId, { mfaEnabled: true });
    
    return {
      accessToken: this.generateAccessToken(updatedUser),
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        role: updatedUser.role,
        mfaEnabled: updatedUser.mfaEnabled,
      },
    };
  }

  async verifyMfaLogin(tempToken: string, code: string) {
    let payload: any;
    try {
      payload = this.jwtService.verify(tempToken);
    } catch (e) {
      throw new UnauthorizedException('Invalid or expired temporary token');
    }

    if (!payload.mfaRequired) {
      throw new UnauthorizedException('Invalid token type');
    }

    const username = payload.username;
    const user = await this.usersService.findByUsername(username, true);

    if (!user || !user.mfaSecret) {
      throw new UnauthorizedException('MFA configuration mismatch');
    }

    const isValid = authenticator.check(code, user.mfaSecret);

    if (!isValid) {
      throw new UnauthorizedException('Invalid verification code');
    }

    const { passwordHash, mfaSecret, ...safeUser } = user;

    return {
      accessToken: this.generateAccessToken(user),
      user: safeUser,
    };
  }
}
