import { Controller, Post, Body, UseGuards, Request, UnauthorizedException, UseInterceptors } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AuditAction } from '../audit/audit-action.decorator';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
@UseInterceptors(AuditLogInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @AuditAction('Login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto.username, loginDto.password);
  }

  @Post('signup')
  @Throttle({ default: { limit: 3, ttl: 3600000 } })
  @AuditAction('Signup')
  async signup(@Body() body: any) {
    return this.authService.signup(body.username, body.password);
  }

  @Post('mfa/setup')
  @UseGuards(JwtAuthGuard)
  @AuditAction('Setup MFA')
  async setupMfa(@Request() req) {
    return this.authService.setupMfa(req.user.id);
  }

  @Post('mfa/setup/verify')
  @UseGuards(JwtAuthGuard)
  @AuditAction('Verify MFA')
  async verifyMfaSetup(@Request() req, @Body('code') code: string) {
    if (!code) {
      throw new UnauthorizedException('MFA code is required');
    }
    return this.authService.verifyMfaSetup(req.user.id, code);
  }

  @Post('mfa/verify')
  @AuditAction('Verify MFA')
  async verifyMfaLogin(@Body() body: any) {
    if (!body.tempToken || !body.code) {
      throw new UnauthorizedException('Invalid request parameters');
    }
    return this.authService.verifyMfaLogin(body.tempToken, body.code);
  }
}
