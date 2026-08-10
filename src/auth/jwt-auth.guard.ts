import { ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authenticated = await super.canActivate(context);
    if (!authenticated) return false;

    const request = context.switchToHttp().getRequest();
    const path = request.path || request.originalUrl || '';
    const canViewOwnProfile = request.method === 'GET' && /\/users\/me\/?(?:\?.*)?$/.test(path);
    const canChangeOwnPassword = request.method === 'PUT' && /\/users\/me\/?(?:\?.*)?$/.test(path);
    const isMfaEnrollment = /\/auth\/mfa\/setup(?:\/verify)?\/?(?:\?.*)?$/.test(path);

    if (request.user?.mustChangePassword && !canViewOwnProfile && !canChangeOwnPassword && !isMfaEnrollment) {
      throw new ForbiddenException('Password change required before accessing the application');
    }

    return true;
  }
}
