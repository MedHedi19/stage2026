import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Report } from './entities/report.entity';
import { WazuhService } from '../wazuh/wazuh.service';
import PDFDocument from 'pdfkit';
import { Workbook } from 'exceljs';

@Injectable()
export class ReportsService {
  constructor(
    @InjectRepository(Report)
    private readonly reportRepository: Repository<Report>,
    private readonly wazuhService: WazuhService,
  ) {}

  async generateReport(
    userId: number,
    username: string,
    format: 'pdf' | 'excel',
    filters: { severity?: number; ip?: string; startDate?: string; endDate?: string },
  ): Promise<{ buffer: Buffer; filename: string }> {
    // 1. Fetch filtered alerts from Wazuh integration
    const alerts = await this.wazuhService.fetchRecentAlerts({
      severity: filters.severity,
      ip: filters.ip,
      startDate: filters.startDate,
      endDate: filters.endDate,
      limit: 1000, // retrieve a rich batch for reporting
    });

    // 2. Filter and process alerts for SOC relevance
    const processedAlerts = this.processAlertsForSOC(alerts);

    // 3. Generate appropriate document buffer
    let buffer: Buffer;
    let filename: string;
    const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');

    if (format === 'pdf') {
      buffer = await this.generatePdfBuffer(processedAlerts, filters);
      filename = `security-report-${timestampStr}.pdf`;
    } else {
      buffer = await this.generateExcelBuffer(processedAlerts, filters);
      filename = `security-report-${timestampStr}.xlsx`;
    }

    // 4. Insert metadata record in MySQL database
    const report = this.reportRepository.create({
      userId,
      username,
      format,
      filters: JSON.stringify(filters),
    });
    await this.reportRepository.save(report);

    return { buffer, filename };
  }

  private processAlertsForSOC(alerts: any[]) {
    // Noise patterns to filter out
    const noisePatterns = [
      'dpkg', 'apt', 'npm', 'yarn', 'pip', // package managers
      'apparmor.*DENIED', // normal apparmor denials
      'pam.*session opened', 'pam.*session closed', // normal logins
      'systemd.*started', 'systemd.*stopped', // normal service changes
      'cron.*\(root\) CMD', // normal cron jobs
    ];

    // Filter out noise and keep security-relevant alerts
    const securityAlerts = alerts.filter(alert => {
      const description = alert.rule.description.toLowerCase();
      const groups = alert.rule.groups || [];
      
      // Keep if high severity (>= 5)
      if (alert.rule.level >= 5) return true;
      
      // Keep if security-related groups
      const securityGroups = ['ids', 'suricata', 'authentication_failed', 'attack', 'malware', 'vulnerability'];
      if (groups.some(g => securityGroups.includes(g.toLowerCase()))) return true;
      
      // Filter out noise patterns
      const isNoise = noisePatterns.some(pattern => 
        new RegExp(pattern, 'i').test(description)
      );
      return !isNoise;
    });

    // Sort by severity (highest first) then by time (newest first)
    securityAlerts.sort((a, b) => {
      if (b.rule.level !== a.rule.level) {
        return b.rule.level - a.rule.level;
      }
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });

    // Group repetitive events
    const groupedAlerts = this.groupAlerts(securityAlerts);

    return {
      summary: this.generateSummary(alerts, securityAlerts, groupedAlerts),
      alerts: groupedAlerts,
      totalRaw: alerts.length,
      totalSecurity: securityAlerts.length,
    };
  }

  private generateSummary(rawAlerts: any[], securityAlerts: any[], groupedAlerts: any[]) {
    const severityCounts: Record<string, number> = {};
    securityAlerts.forEach(alert => {
      const level = alert.rule.level;
      severityCounts[level] = (severityCounts[level] || 0) + 1;
    });

    const topSourceIPs: Record<string, number> = {};
    securityAlerts.forEach(alert => {
      const ip = alert.data.src_ip || 'unknown';
      topSourceIPs[ip] = (topSourceIPs[ip] || 0) + 1;
    });

    return {
      period: `${new Date(rawAlerts[rawAlerts.length - 1]?.timestamp).toLocaleDateString()} - ${new Date(rawAlerts[0]?.timestamp).toLocaleDateString()}`,
      totalRawEvents: rawAlerts.length,
      totalSecurityEvents: securityAlerts.length,
      noiseFiltered: rawAlerts.length - securityAlerts.length,
      severityDistribution: severityCounts,
      topSourceIPs: Object.entries(topSourceIPs)
        .sort((a, b) => (b[1] as number) - (a[1] as number))
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
    };
  }

  private groupAlerts(alerts: any[]) {
    const groups = {};
    
    alerts.forEach(alert => {
      const key = `${alert.rule.description}_${alert.data.src_ip || 'unknown'}_${alert.data.dest_ip || 'unknown'}`;
      if (!groups[key]) {
        groups[key] = {
          ...alert,
          count: 1,
          firstSeen: alert.timestamp,
          lastSeen: alert.timestamp,
        };
      } else {
        groups[key].count++;
        groups[key].lastSeen = alert.timestamp;
      }
    });

    return Object.values(groups);
  }

  async getHistory(): Promise<Report[]> {
    return this.reportRepository.find({
      order: {
        createdAt: 'DESC',
      },
    });
  }

  private async generatePdfBuffer(processedData: any, filters: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];
        const { summary, alerts } = processedData;

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        // Document Header
        doc.fontSize(20).text('IDS/IPS Security Report', { align: 'center' });
        doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.moveDown();

        // Executive Summary
        doc.fontSize(14).text('Executive Summary');
        doc.fontSize(10).text(`Report Period: ${summary.period}`);
        doc.text(`Total Raw Events: ${summary.totalRawEvents}`);
        doc.text(`Security Events: ${summary.totalSecurityEvents}`);
        doc.text(`Noise Filtered: ${summary.noiseFiltered}`);
        doc.moveDown();

        // Severity Distribution
        doc.fontSize(12).text('Severity Distribution');
        Object.entries(summary.severityDistribution).forEach(([level, count]) => {
          doc.fontSize(10).text(`Level ${level}: ${count} events`);
        });
        doc.moveDown();

        // Top Source IPs
        doc.fontSize(12).text('Top Source IPs');
        summary.topSourceIPs.forEach(({ ip, count }: any) => {
          doc.fontSize(10).text(`${ip}: ${count} events`);
        });
        doc.moveDown();

        // Severity Distribution Chart
        if (Object.keys(summary.severityDistribution).length > 0) {
          doc.fontSize(12).text('Severity Distribution Chart');
          doc.moveDown();
          
          const chartX = 50;
          const chartY = doc.y;
          const chartWidth = 500;
          const chartHeight = 150;
          const severityKeys = Object.keys(summary.severityDistribution);
          const barWidth = chartWidth / severityKeys.length - 10;
          const severityValues = Object.values(summary.severityDistribution) as number[];
          const maxCount = Math.max(...severityValues);
          
          doc.rect(chartX, chartY, chartWidth, chartHeight).stroke();
          
          Object.entries(summary.severityDistribution).forEach(([level, count], index) => {
            const countNum = count as number;
            const barHeight = (countNum / maxCount) * (chartHeight - 20);
            const x = chartX + 10 + index * (barWidth + 10);
            const y = chartY + chartHeight - barHeight - 10;
            
            // Color based on severity
            const colors: Record<string, string> = {
              '3': '#FFA500', // orange
              '4': '#FF6347', // tomato
              '5': '#FF4500', // orange red
              '6': '#DC143C', // crimson
              '7': '#B22222', // fire brick
              '8': '#8B0000', // dark red
              '9': '#800000', // maroon
              '10': '#000000', // black
            };
            doc.rect(x, y, barWidth, barHeight).fill(colors[level] || '#4169E1');
            
            doc.fontSize(8).fillColor('black').text(`L${level}`, x, chartY + chartHeight + 5);
            doc.text(countNum.toString(), x + barWidth/2 - 5, y - 10);
          });
          
          doc.moveDown(20);
        }

        // Top Source IPs Chart
        if (summary.topSourceIPs.length > 0) {
          doc.fontSize(12).text('Top Source IPs Chart');
          doc.moveDown();
          
          const chartX = 50;
          const chartY = doc.y;
          const chartWidth = 500;
          const chartHeight = 150;
          const barWidth = chartWidth / summary.topSourceIPs.length - 10;
          const maxCount = Math.max(...summary.topSourceIPs.map((ip: any) => ip.count));
          
          doc.rect(chartX, chartY, chartWidth, chartHeight).stroke();
          
          summary.topSourceIPs.forEach(({ ip, count }: any, index) => {
            const barHeight = (count / maxCount) * (chartHeight - 20);
            const x = chartX + 10 + index * (barWidth + 10);
            const y = chartY + chartHeight - barHeight - 10;
            
            doc.rect(x, y, barWidth, barHeight).fill('#4169E1');
            
            doc.fontSize(7).fillColor('black').text(ip.substring(0, 15), x, chartY + chartHeight + 5);
            doc.text(count.toString(), x + barWidth/2 - 5, y - 10);
          });
          
          doc.moveDown(20);
        }

        // Security Alerts
        doc.fontSize(14).text('Security Alert Details');
        doc.moveDown();

        if (alerts.length === 0) {
          doc.fontSize(10).text('No security alerts found for the selected filters.');
        } else {
          alerts.forEach((alert: any, index: number) => {
            if (doc.y > 700) {
              doc.addPage();
            }

            doc.fontSize(11).text(`${index + 1}. [Level ${alert.rule.level}] ${alert.rule.description}`);
            if (alert.count > 1) {
              doc.fontSize(9).text(`   Occurrences: ${alert.count} (First: ${alert.firstSeen}, Last: ${alert.lastSeen})`);
            } else {
              doc.fontSize(9).text(`   Time: ${alert.timestamp}`);
            }
            doc.text(`   Agent: ${alert.agent.name} (${alert.agent.ip || 'N/A'})`);
            doc.text(`   Source: ${alert.data.src_ip || 'N/A'} -> Dest: ${alert.data.dest_ip || 'N/A'}`);
            doc.moveDown();
          });
        }

        doc.end();
      } catch (err) {
        reject(err);
      }
    });
  }

  private async generateExcelBuffer(processedData: any, filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const { summary, alerts } = processedData;
    
    // Summary Sheet
    const summarySheet = workbook.addWorksheet('Executive Summary');
    summarySheet.addRow(['IDS/IPS Security Report']);
    summarySheet.addRow([`Report Generated: ${new Date().toLocaleString()}`]);
    summarySheet.addRow([`Report Period: ${summary.period}`]);
    summarySheet.addRow([]);
    summarySheet.addRow(['Total Raw Events', summary.totalRawEvents]);
    summarySheet.addRow(['Security Events', summary.totalSecurityEvents]);
    summarySheet.addRow(['Noise Filtered', summary.noiseFiltered]);
    summarySheet.addRow([]);
    
    summarySheet.addRow(['Severity Distribution']);
    Object.entries(summary.severityDistribution).forEach(([level, count]) => {
      summarySheet.addRow([`Level ${level}`, count]);
    });
    
    summarySheet.addRow([]);
    summarySheet.addRow(['Top Source IPs']);
    summary.topSourceIPs.forEach(({ ip, count }: any) => {
      summarySheet.addRow([ip, count]);
    });

    // Add simple chart to summary sheet
    if (Object.keys(summary.severityDistribution).length > 0) {
      summarySheet.addRow([]);
      summarySheet.addRow(['Severity Distribution']);
      Object.entries(summary.severityDistribution).forEach(([level, count]) => {
        summarySheet.addRow([`Level ${level}`, count]);
      });
    }

    // Alerts Sheet
    const alertsSheet = workbook.addWorksheet('Security Alerts');
    alertsSheet.addRow(['IDS/IPS Cybersecurity Alert Report']);
    alertsSheet.addRow([`Report Generated On: ${new Date().toLocaleString()}`]);
    alertsSheet.addRow([`Filters: ${JSON.stringify(filters)}`]);
    alertsSheet.addRow([]);

    alertsSheet.getRow(1).font = { size: 16, bold: true };
    alertsSheet.getRow(2).font = { italic: true };

    // Columns
    alertsSheet.columns = [
      { header: 'Alert ID', key: 'id', width: 25 },
      { header: 'Timestamp', key: 'timestamp', width: 25 },
      { header: 'Severity Level', key: 'level', width: 15 },
      { header: 'Rule ID', key: 'ruleId', width: 12 },
      { header: 'Description', key: 'description', width: 45 },
      { header: 'Agent ID', key: 'agentId', width: 12 },
      { header: 'Agent Name', key: 'agentName', width: 20 },
      { header: 'Source IP', key: 'srcIp', width: 20 },
      { header: 'Destination IP', key: 'destIp', width: 20 },
      { header: 'Protocol', key: 'protocol', width: 12 },
      { header: 'Occurrences', key: 'count', width: 12 },
    ];

    alerts.forEach((alert: any) => {
      alertsSheet.addRow({
        id: alert.id,
        timestamp: alert.count > 1 ? `${alert.firstSeen} - ${alert.lastSeen}` : alert.timestamp,
        level: alert.rule.level,
        ruleId: alert.rule.id,
        description: alert.rule.description,
        agentId: alert.agent.id,
        agentName: alert.agent.name,
        srcIp: alert.data.src_ip || 'N/A',
        destIp: alert.data.dest_ip || 'N/A',
        protocol: alert.data.protocol || 'N/A',
        count: alert.count || 1,
      });
    });

    // Style column header row (which is row 5, since we added 4 rows at top)
    const headerRowIdx = 5;
    const headerRow = alertsSheet.getRow(headerRowIdx);
    headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    headerRow.eachCell(cell => {
      cell.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF0B192C' },
      };
    });

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer as any);
  }
}
