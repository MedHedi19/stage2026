import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { AuditService } from './audit.service';
import { AUDIT_ACTION_KEY } from './audit-action.decorator';

@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  constructor(
    private reflector: Reflector,
    private auditService: AuditService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const action = this.reflector.get<string>(
      AUDIT_ACTION_KEY,
      context.getHandler(),
    );

    if (!action) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const ipAddress = request.headers['x-forwarded-for'] || request.ip || request.connection?.remoteAddress;

    return next.handle().pipe(
      tap({
        next: (data) => {
          let userId = user?.id || null;
          let username = user?.username || null;

          // For login, request.user isn't set yet, but the handler returns the authenticated user
          if ((action === 'Login' || action === 'Verify MFA') && data && data.user) {
            userId = data.user.id;
            username = data.user.username;
          }

          // Extract targetEntity from req.params or req.body if applicable
          let targetEntity: string | undefined = undefined;
          if (request.params && Object.keys(request.params).length > 0) {
            targetEntity = JSON.stringify(request.params);
          } else if (request.body && request.body.username) {
            targetEntity = `user:${request.body.username}`;
          }

          this.auditService.log(
            userId,
            username,
            action,
            targetEntity,
            Array.isArray(ipAddress) ? ipAddress[0] : ipAddress,
          ).catch(err => {
            console.error('AuditLogInterceptor failed to save log:', err);
          });
        },
      }),
    );
  }
}
