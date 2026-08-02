import { ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  async canActivate(context: ExecutionContext) {
    const can = (await super.canActivate(context)) as boolean;
    if (!can) return false;

    const req = context.switchToHttp().getRequest();
    const user = req.user as { mfaEnabled?: boolean } | undefined;
    if (!user) return true;
    if (user.mfaEnabled) return true;

    const url: string = req.originalUrl || req.url || '';
    if (url.startsWith('/auth/mfa') || url.startsWith('/users/me')) {
      return true;
    }

    throw new ForbiddenException('MFA setup required');
  }
}
