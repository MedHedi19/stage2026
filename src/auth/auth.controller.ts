import { Controller, Post, Body, UseGuards, Request, UnauthorizedException, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AuditAction } from '../audit/audit-action.decorator';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';

@Controller('auth')
@UseInterceptors(AuditLogInterceptor)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @AuditAction('Login')
  async login(@Body() body: any) {
    return this.authService.login(body.username, body.password);
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
      throw new UnauthorizedException('tempToken and code are required');
    }
    return this.authService.verifyMfaLogin(body.tempToken, body.code);
  }
}
