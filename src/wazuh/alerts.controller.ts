import { Controller, Get, Query, UseGuards, UseInterceptors } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { WazuhService } from './wazuh.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from '../users/entities/user.entity';
import { AuditAction } from '../audit/audit-action.decorator';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';

@Controller('alerts')
@UseGuards(JwtAuthGuard, RolesGuard)
@UseInterceptors(AuditLogInterceptor)
export class AlertsController {
  constructor(private readonly wazuhService: WazuhService) {}

  @Get()
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @Throttle({ default: { limit: 50, ttl: 60000 } })
  @AuditAction('View Alerts')
  async getAlerts(
    @Query('severity') severity?: string,
    @Query('ip') ip?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ) {
    return this.wazuhService.fetchRecentAlerts({
      severity: severity ? parseInt(severity, 10) : undefined,
      ip,
      startDate,
      endDate,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
  }

  @Get('stats')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  async getStats(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ) {
    return this.wazuhService.getAlertStats({ startDate, endDate });
  }
}
