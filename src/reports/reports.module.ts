import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Report } from './entities/report.entity';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';
import { WazuhModule } from '../wazuh/wazuh.module';
import { AuditModule } from '../audit/audit.module';
import { FirewallModule } from '../firewall/firewall.module';
import { ExecutiveSummaryGenerator } from './generators/executive-summary.generator';
import { IncidentDetailGenerator } from './generators/incident-detail.generator';
import { ThreatIntelligenceGenerator } from './generators/threat-intelligence.generator';
import { UserActivityGenerator } from './generators/user-activity.generator';
import { FirewallListTrafficGenerator } from './generators/firewall-list-traffic.generator';
import { BlacklistEntry } from '../firewall/entities/blacklist-entry.entity';
import { WhitelistEntry } from '../firewall/entities/whitelist-entry.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Report, BlacklistEntry, WhitelistEntry]), WazuhModule, AuditModule, FirewallModule],
  controllers: [ReportsController],
  providers: [
    ReportsService,
    ExecutiveSummaryGenerator,
    IncidentDetailGenerator,
    ThreatIntelligenceGenerator,
    UserActivityGenerator,
    FirewallListTrafficGenerator,
  ],
  exports: [ReportsService],
})
export class ReportsModule {}
