import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Report } from './entities/report.entity';
import { ReportType } from './report-types.enum';
import { ReportGenerator } from './interfaces/report-generator.interface';
import { ExecutiveSummaryGenerator } from './generators/executive-summary.generator';
import { IncidentDetailGenerator } from './generators/incident-detail.generator';
import { ThreatIntelligenceGenerator } from './generators/threat-intelligence.generator';
import { UserActivityGenerator } from './generators/user-activity.generator';

@Injectable()
export class ReportsService {
  private generators: Map<ReportType, ReportGenerator>;

  constructor(
    @InjectRepository(Report)
    private readonly reportRepository: Repository<Report>,
    private readonly executiveSummaryGenerator: ExecutiveSummaryGenerator,
    private readonly incidentDetailGenerator: IncidentDetailGenerator,
    private readonly threatIntelligenceGenerator: ThreatIntelligenceGenerator,
    private readonly userActivityGenerator: UserActivityGenerator,
  ) {
    // Initialize generators map
    this.generators = new Map([
      [ReportType.EXECUTIVE_SUMMARY, this.executiveSummaryGenerator],
      [ReportType.INCIDENT_DETAIL, this.incidentDetailGenerator],
      [ReportType.THREAT_INTELLIGENCE, this.threatIntelligenceGenerator],
      [ReportType.USER_ACTIVITY, this.userActivityGenerator],
    ]);
  }

  async generateReport(
    userId: number,
    username: string,
    format: 'pdf' | 'excel',
    filters: { severity?: number; ip?: string; startDate?: string; endDate?: string },
    reportType: ReportType = ReportType.EXECUTIVE_SUMMARY,
  ): Promise<{ buffer: Buffer; filename: string }> {
    // Get the appropriate generator
    const generator = this.generators.get(reportType);
    if (!generator) {
      throw new Error(`No generator found for report type: ${reportType}`);
    }

    // Generate the report using the appropriate generator
    const { buffer, filename } = await generator.generate({
      userId,
      username,
      format,
      filters,
    });

    // Insert metadata record in MySQL database
    const report = this.reportRepository.create({
      userId,
      username,
      format,
      reportType,
      filters: JSON.stringify(filters),
    });
    await this.reportRepository.save(report);

    return { buffer, filename };
  }

  async getHistory(): Promise<any[]> {
    const reports = await this.reportRepository.find({
      order: { createdAt: 'DESC' },
      relations: { user: true },
    });
    return reports.map((r) => ({
      id: r.id,
      createdBy: r.username || r.user?.username || '—',
      format: r.format,
      reportType: r.reportType,
      filename: `${r.reportType}-report-${r.createdAt.toISOString().replace(/[:.]/g, '-')}.${r.format === 'excel' ? 'xlsx' : r.format}`,
      createdAt: r.createdAt,
    }));
  }
}