import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Report } from './entities/report.entity';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';
import { WazuhModule } from '../wazuh/wazuh.module';
import { AuditModule } from '../audit/audit.module';
import { ExecutiveSummaryGenerator } from './generators/executive-summary.generator';
import { IncidentDetailGenerator } from './generators/incident-detail.generator';
import { ThreatIntelligenceGenerator } from './generators/threat-intelligence.generator';
import { UserActivityGenerator } from './generators/user-activity.generator';

@Module({
  imports: [TypeOrmModule.forFeature([Report]), WazuhModule, AuditModule],
  controllers: [ReportsController],
  providers: [
    ReportsService,
    ExecutiveSummaryGenerator,
    IncidentDetailGenerator,
    ThreatIntelligenceGenerator,
    UserActivityGenerator,
  ],
  exports: [ReportsService],
})
export class ReportsModule {}
