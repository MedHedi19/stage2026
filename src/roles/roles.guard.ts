import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from '../users/entities/user.entity';
import { ROLES_KEY } from './roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    console.log('[RolesGuard] Required roles:', requiredRoles);
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();
    console.log('[RolesGuard] User from request:', user);
    console.log('[RolesGuard] User role:', user?.role);
    if (!user || !user.role) {
      console.log('[RolesGuard] No user or role found');
      throw new ForbiddenException('Access denied: authentication required');
    }
    if (!requiredRoles.includes(user.role)) {
      console.log('[RolesGuard] Role mismatch. Required:', requiredRoles, 'Got:', user.role);
      throw new ForbiddenException('Access denied: insufficient permissions');
    }
    console.log('[RolesGuard] Access granted');
    return true;
  }
}
