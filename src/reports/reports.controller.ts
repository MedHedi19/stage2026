import { Controller, Post, Get, Body, UseGuards, Request, Res, UseInterceptors } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import * as express from 'express';
import { ReportsService } from './reports.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from '../users/entities/user.entity';
import { AuditAction } from '../audit/audit-action.decorator';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';

@Controller('reports')
@UseGuards(JwtAuthGuard, RolesGuard)
@UseInterceptors(AuditLogInterceptor)
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Post('generate')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @AuditAction('Generate report')
  async generateReport(
    @Request() req,
    @Body() body: any,
    @Res() res: express.Response,
  ) {
    const { format, severity, ip, startDate, endDate } = body;
    const filters = {
      severity: severity ? parseInt(severity, 10) : undefined,
      ip,
      startDate,
      endDate,
    };

    const { buffer, filename } = await this.reportsService.generateReport(
      req.user.id,
      req.user.username,
      format || 'pdf',
      filters,
    );

    const contentType =
      format === 'excel'
        ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        : 'application/pdf';

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
    res.send(buffer);
  }

  @Get('history')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  async getHistory() {
    return this.reportsService.getHistory();
  }
}
