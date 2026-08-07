import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Report } from './entities/report.entity';
import { WazuhService } from '../wazuh/wazuh.service';
import { AuditService } from '../audit/audit.service';
import PDFDocument from 'pdfkit';
import { Workbook } from 'exceljs';
import { ChartJSNodeCanvas } from 'chartjs-node-canvas';
import {
  classifyAlertCategory,
  consolidateCategories,
} from '../common/alert-classifier';
import { ReportType } from './report-types.enum';

@Injectable()
export class ReportsService {
  constructor(
    @InjectRepository(Report)
    private readonly reportRepository: Repository<Report>,
    private readonly wazuhService: WazuhService,
    private readonly auditService: AuditService,
  ) {}

  async generateReport(
    userId: number,
    username: string,
    reportType: ReportType,
    format: 'pdf' | 'excel',
    filters: { severity?: number; ip?: string; startDate?: string; endDate?: string },
  ): Promise<{ buffer: Buffer; filename: string }> {
    // Route to appropriate report generator based on type
    let buffer: Buffer;
    let filename: string;
    const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');

    switch (reportType) {
      case ReportType.USER_ACTIVITY:
        buffer = await this.generateUserActivityReport(format, filters);
        filename = `user-activity-report-${timestampStr}.${format === 'excel' ? 'xlsx' : 'pdf'}`;
        break;
      case ReportType.EXECUTIVE_SUMMARY:
        buffer = await this.generateExecutiveSummaryReport(format, filters);
        filename = `executive-summary-report-${timestampStr}.${format === 'excel' ? 'xlsx' : 'pdf'}`;
        break;
      case ReportType.THREAT_INTELLIGENCE:
        buffer = await this.generateThreatIntelligenceReport(format, filters);
        filename = `threat-intelligence-report-${timestampStr}.${format === 'excel' ? 'xlsx' : 'pdf'}`;
        break;
      case ReportType.INCIDENT_DETAIL:
        buffer = await this.generateIncidentDetailReport(format, filters);
        filename = `incident-detail-report-${timestampStr}.${format === 'excel' ? 'xlsx' : 'pdf'}`;
        break;
      default:
        // Default to original behavior for backward compatibility
        const alerts = await this.wazuhService.fetchRecentAlerts({
          severity: filters.severity,
          ip: filters.ip,
          startDate: filters.startDate,
          endDate: filters.endDate,
          limit: 1000,
        });
        const processedAlerts = this.processAlertsForSOC(alerts);
        
        if (format === 'pdf') {
          buffer = await this.generatePdfBuffer(processedAlerts, filters);
          filename = `security-report-${timestampStr}.pdf`;
        } else {
          buffer = await this.generateExcelBuffer(processedAlerts, filters);
          filename = `security-report-${timestampStr}.xlsx`;
        }
    }

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
      reportType: r.reportType || 'standard',
      filename: `security-report-${r.createdAt.toISOString().replace(/[:.]/g, '-')}.${r.format === 'excel' ? 'xlsx' : r.format}`,
      createdAt: r.createdAt,
    }));
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
      const description = (alert.rule.description || '').toLowerCase();
      const groups = alert.rule.groups || [];

      // Security groups: always kept regardless of level
      const securityGroups = ['ids', 'suricata', 'authentication_failed', 'attack', 'malware', 'vulnerability'];
      if (groups.some(g => securityGroups.includes(g.toLowerCase()))) return true;

      // Noise: excluded regardless of level (dpkg, apparmor DENIED normal, etc.)
      const isNoise = noisePatterns.some(pattern => 
        new RegExp(pattern, 'i').test(description)
      );
      if (isNoise) return false;

      // Otherwise, keep only if significant severity
      return alert.rule.level >= 5;
    });

    // Sort: prioritize security groups first, then by severity, then by time
    const priorityGroups = ['ids', 'suricata', 'attack', 'authentication_failed'];
    securityAlerts.sort((a, b) => {
      const aPriority = a.rule.groups?.some(g => priorityGroups.includes(g.toLowerCase())) ? 1 : 0;
      const bPriority = b.rule.groups?.some(g => priorityGroups.includes(g.toLowerCase())) ? 1 : 0;
      if (aPriority !== bPriority) return bPriority - aPriority;
      if (b.rule.level !== a.rule.level) return b.rule.level - a.rule.level;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });

    // Group repetitive events into incidents
    const incidents = this.groupAlerts(securityAlerts);

    return {
      summary: this.generateSummary(alerts, securityAlerts),
      incidents: incidents,
      rawAlerts: securityAlerts,
      totalRaw: alerts.length,
      totalSecurity: securityAlerts.length,
    };
  }

  private generateSummary(rawAlerts: any[], securityAlerts: any[]) {
    const severityCounts: Record<string, number> = {};
    const attacksByType: Record<string, number> = {};
    const alertOverTime: Record<string, number> = {};

    securityAlerts.forEach(alert => {
      const level = alert.rule.level;
      severityCounts[level] = (severityCounts[level] || 0) + 1;

      // Grouping by type — detailed classification (no vague "Autre")
      const category = classifyAlertCategory(alert);
      attacksByType[category] = (attacksByType[category] || 0) + 1;

      // Over time (grouped by hour)
      const dateStr = alert.timestamp ? alert.timestamp.substring(0, 13) + ':00:00Z' : 'Unknown';
      alertOverTime[dateStr] = (alertOverTime[dateStr] || 0) + 1;
    });

    const topSourceIPs: Record<string, number> = {};
    securityAlerts.forEach(alert => {
      const ip = alert.data?.src_ip;
      if (!ip) return; // local system event, no network source
      topSourceIPs[ip] = (topSourceIPs[ip] || 0) + 1;
    });

    const overTimeList = Object.entries(alertOverTime)
      .map(([time, count]) => ({ time, count }))
      .sort((a, b) => a.time.localeCompare(b.time));

    return {
      period: rawAlerts.length > 0 ? `${new Date(rawAlerts[rawAlerts.length - 1]?.timestamp).toLocaleDateString()} - ${new Date(rawAlerts[0]?.timestamp).toLocaleDateString()}` : 'N/A',
      totalRawEvents: rawAlerts.length,
      totalSecurityEvents: securityAlerts.length,
      noiseFiltered: rawAlerts.length - securityAlerts.length,
      severityDistribution: severityCounts,
      attacksByType: consolidateCategories(attacksByType),
      alertsOverTime: overTimeList,
      topSourceIPs: Object.entries(topSourceIPs)
        .sort((a, b) => (b[1] as number) - (a[1] as number))
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
    };
  }

  private groupAlerts(alerts: any[]) {
    const groups = {};
    
    alerts.forEach(alert => {
      const key = `${alert.rule.description}_${alert.data?.src_ip || 'unknown'}_${alert.data?.dest_ip || 'unknown'}`;
      if (!groups[key]) {
        groups[key] = {
          ...alert,
          count: 1,
          firstSeen: alert.timestamp,
          lastSeen: alert.timestamp,
        };
      } else {
        groups[key].count++;
        if (new Date(alert.timestamp) < new Date(groups[key].firstSeen)) {
          groups[key].firstSeen = alert.timestamp;
        }
        if (new Date(alert.timestamp) > new Date(groups[key].lastSeen)) {
          groups[key].lastSeen = alert.timestamp;
        }
      }
    });

    return Object.values(groups);
  }



  private async generatePdfBuffer(processedData: any, filters: any): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];
        const { summary, incidents, rawAlerts } = processedData;

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        const addSectionHeader = (title: string) => {
          doc.moveDown();
          doc.fontSize(16).fillColor('#0b192c').text(title, { underline: true });
          doc.fillColor('black').moveDown(0.5);
        };

        // Document Header
        doc.fontSize(22).text('Rapport de Sécurité SOC', { align: 'center' });
        doc.fontSize(12).fillColor('gray').text(`Généré le: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.fillColor('black');
        doc.moveDown();

        // 1. Tableau de bord
        addSectionHeader('1. Tableau de bord');
        
        doc.fontSize(12).text('Répartition par type d\'attaque:');
        doc.moveDown(0.5);
        
        const typeChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const typeChartBuffer = await typeChartCanvas.renderToBuffer({
            type: 'bar',
            data: {
                labels: Object.keys(summary.attacksByType),
                datasets: [{
                    label: 'Attaques',
                    data: Object.values(summary.attacksByType),
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: { display: false },
                    legend: { display: false }
                }
            }
        } as any);

        doc.image(typeChartBuffer, { width: 450 });
        doc.moveDown();

        doc.font('Helvetica').fontSize(12).text('Évolution dans le temps:');
        doc.moveDown(0.5);
        
        const timeChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const timeChartBuffer = await timeChartCanvas.renderToBuffer({
            type: 'line',
            data: {
                labels: summary.alertsOverTime.map((a: any) => new Date(a.time).toLocaleString()),
                datasets: [{
                    label: 'Nombre d\'alertes',
                    data: summary.alertsOverTime.map((a: any) => a.count),
                    backgroundColor: 'rgba(255, 99, 132, 0.5)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1,
                    fill: true
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        } as any);

        doc.image(timeChartBuffer, { width: 450 });
        doc.font('Helvetica').moveDown();

        // 2. Statistiques
        addSectionHeader('2. Statistiques');
        doc.fontSize(10).text(`Période d'analyse: ${summary.period}`);
        doc.text(`Total événements bruts: ${summary.totalRawEvents}`);
        doc.text(`Événements de sécurité (filtrés): ${summary.totalSecurityEvents}`);
        doc.text(`Bruit écarté: ${summary.noiseFiltered}`);
        doc.moveDown();

        doc.fontSize(12).text('Distribution par Sévérité:');
        Object.entries(summary.severityDistribution).forEach(([level, count]) => {
          doc.fontSize(10).text(`- Niveau ${level}: ${count} événements`);
        });
        doc.moveDown();

        doc.fontSize(12).text('Top 5 IPs Sources:');
        if (summary.topSourceIPs.length === 0) {
          doc.fontSize(10).text('- Aucune IP source externe détectée.');
        } else {
          summary.topSourceIPs.forEach(({ ip, count }: any) => {
            doc.fontSize(10).text(`- ${ip}: ${count} requêtes`);
          });
        }
        doc.moveDown();

        // 3. Incidents
        doc.addPage();
        addSectionHeader('3. Incidents (Alertes Groupées)');
        if (incidents.length === 0) {
          doc.fontSize(10).text('Aucun incident détecté.');
        } else {
          incidents.forEach((incident: any, index: number) => {
            if (doc.y > 700) doc.addPage();
            doc.fontSize(11).font('Helvetica-Bold').text(`${index + 1}. [Niv ${incident.rule.level}] ${incident.rule.description}`);
            doc.font('Helvetica').fontSize(9);
            doc.text(`   Occurrences: ${incident.count}`);
            doc.text(`   Première vue: ${new Date(incident.firstSeen).toLocaleString()}`);
            doc.text(`   Dernière vue: ${new Date(incident.lastSeen).toLocaleString()}`);
            doc.text(`   Source: ${incident.data?.src_ip || 'N/A'} -> Dest: ${incident.data?.dest_ip || 'N/A'}`);
            doc.moveDown();
          });
        }

        // 4. Alertes
        doc.addPage();
        addSectionHeader('4. Alertes de Sécurité (Détail)');
        if (rawAlerts.length === 0) {
          doc.fontSize(10).text('Aucune alerte de sécurité pertinente.');
        } else {
          const maxAlertsToPrint = Math.min(rawAlerts.length, 200); // limit to avoid huge PDFs
          for(let i = 0; i < maxAlertsToPrint; i++) {
            const alert = rawAlerts[i];
            if (doc.y > 750) doc.addPage();
            doc.fontSize(9).font('Helvetica-Bold').text(`[${new Date(alert.timestamp).toLocaleString()}] Niv ${alert.rule.level} - ${alert.rule.description}`);
            doc.font('Helvetica').fontSize(8);
            doc.text(`   Agent: ${alert.agent?.name || 'N/A'} | Src: ${alert.data?.src_ip || 'N/A'} | Dst: ${alert.data?.dest_ip || 'N/A'}`);
            doc.moveDown(0.5);
          }
          if (rawAlerts.length > maxAlertsToPrint) {
             doc.fontSize(10).font('Helvetica-Oblique').text(`... et ${rawAlerts.length - maxAlertsToPrint} autres alertes omises pour la lisibilité.`);
          }
        }

        doc.end();
      } catch (err) {
        reject(err);
      }
    });
  }

  private async generateExcelBuffer(processedData: any, filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const { summary, incidents, rawAlerts } = processedData;
    
    // 1. Tableau de bord
    const dashSheet = workbook.addWorksheet('Tableau de bord');
    dashSheet.addRow(['Rapport de Sécurité SOC - Tableau de bord']);
    dashSheet.addRow([`Généré le: ${new Date().toLocaleString()}`]);
    dashSheet.addRow([`Période: ${summary.period}`]);
    dashSheet.addRow([]);
    
    dashSheet.addRow(['Attaques par Type', 'Nombre']);
    Object.entries(summary.attacksByType).forEach(([cat, count]) => dashSheet.addRow([cat, count]));
    dashSheet.addRow([]);

    dashSheet.addRow(['Évolution dans le temps', 'Nombre d\'alertes']);
    summary.alertsOverTime.forEach(({ time, count }: any) => dashSheet.addRow([new Date(time).toLocaleString(), count]));

    dashSheet.getColumn(1).width = 30;
    dashSheet.getColumn(2).width = 20;

    // Add charts
    const typeChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 300, backgroundColour: 'white' });
    const typeChartBuffer = await typeChartCanvas.renderToBuffer({
        type: 'bar',
        data: {
            labels: Object.keys(summary.attacksByType),
            datasets: [{
                label: 'Attaques',
                data: Object.values(summary.attacksByType),
                backgroundColor: 'rgba(54, 162, 235, 0.5)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: { plugins: { legend: { display: false } } }
    } as any);

    const typeImageId = workbook.addImage({
        buffer: typeChartBuffer as any,
        extension: 'png',
    });
    
    dashSheet.addImage(typeImageId, {
        tl: { col: 3, row: 4 },
        ext: { width: 500, height: 300 }
    });

    const timeChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 300, backgroundColour: 'white' });
    const timeChartBuffer = await timeChartCanvas.renderToBuffer({
        type: 'line',
        data: {
            labels: summary.alertsOverTime.map((a: any) => new Date(a.time).toLocaleString()),
            datasets: [{
                label: 'Nombre d\'alertes',
                data: summary.alertsOverTime.map((a: any) => a.count),
                backgroundColor: 'rgba(255, 99, 132, 0.5)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1,
                fill: true
            }]
        },
        options: {
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    } as any);

    const timeImageId = workbook.addImage({
        buffer: timeChartBuffer as any,
        extension: 'png',
    });
    
    dashSheet.addImage(timeImageId, {
        tl: { col: 3, row: 20 },
        ext: { width: 500, height: 300 }
    });

    // 2. Statistiques
    const statSheet = workbook.addWorksheet('Statistiques');
    statSheet.addRow(['Métrique', 'Valeur']);
    statSheet.addRow(['Total Événements Bruts', summary.totalRawEvents]);
    statSheet.addRow(['Événements de Sécurité', summary.totalSecurityEvents]);
    statSheet.addRow(['Bruit Écarté', summary.noiseFiltered]);
    statSheet.addRow([]);

    statSheet.addRow(['Sévérité', 'Nombre']);
    Object.entries(summary.severityDistribution).forEach(([level, count]) => {
      statSheet.addRow([`Niveau ${level}`, count]);
    });
    statSheet.addRow([]);

    statSheet.addRow(['Top IP Sources', 'Nombre de requêtes']);
    summary.topSourceIPs.forEach(({ ip, count }: any) => {
      statSheet.addRow([ip, count]);
    });

    statSheet.getColumn(1).width = 30;
    statSheet.getColumn(2).width = 20;

    // 3. Incidents
    const incSheet = workbook.addWorksheet('Incidents');
    incSheet.addRow(['Description', 'Sévérité', 'Occurrences', 'Première Vue', 'Dernière Vue', 'Source IP', 'Dest IP']);
    incSheet.getRow(1).font = { bold: true };
    incSheet.columns = [
      { key: 'desc', width: 50 },
      { key: 'sev', width: 10 },
      { key: 'occ', width: 15 },
      { key: 'first', width: 25 },
      { key: 'last', width: 25 },
      { key: 'src', width: 20 },
      { key: 'dst', width: 20 }
    ];

    incidents.forEach((inc: any) => {
      incSheet.addRow([
        inc.rule.description,
        inc.rule.level,
        inc.count,
        new Date(inc.firstSeen).toLocaleString(),
        new Date(inc.lastSeen).toLocaleString(),
        inc.data?.src_ip || 'N/A',
        inc.data?.dest_ip || 'N/A'
      ]);
    });

    // 4. Alertes
    const alertsSheet = workbook.addWorksheet('Alertes');
    alertsSheet.addRow(['Timestamp', 'Sévérité', 'Règle ID', 'Description', 'Agent', 'Source IP', 'Dest IP', 'Protocole']);
    alertsSheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
    alertsSheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0B192C' } };
    
    alertsSheet.columns = [
      { key: 'time', width: 25 },
      { key: 'sev', width: 10 },
      { key: 'ruleId', width: 12 },
      { key: 'desc', width: 50 },
      { key: 'agent', width: 20 },
      { key: 'src', width: 20 },
      { key: 'dst', width: 20 },
      { key: 'proto', width: 15 }
    ];

    rawAlerts.forEach((alert: any) => {
      alertsSheet.addRow([
        new Date(alert.timestamp).toLocaleString(),
        alert.rule.level,
        alert.rule.id,
        alert.rule.description,
        alert.agent?.name || 'N/A',
        alert.data?.src_ip || 'N/A',
        alert.data?.dest_ip || 'N/A',
        alert.data?.protocol || 'N/A'
      ]);
    });

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer as any);
  }

  // User Activity Report Generator
  private async generateUserActivityReport(format: 'pdf' | 'excel', filters: any): Promise<Buffer> {
    const auditLogs = await this.auditService.findAll({
      startDate: filters.startDate,
      endDate: filters.endDate,
    });

    if (format === 'pdf') {
      return this.generateUserActivityPdf(auditLogs, filters);
    } else {
      return this.generateUserActivityExcel(auditLogs, filters);
    }
  }

  private async generateUserActivityPdf(auditLogs: any[], filters: any): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        const addSectionHeader = (title: string) => {
          doc.moveDown();
          doc.fontSize(16).fillColor('#0b192c').text(title, { underline: true });
          doc.fillColor('black').moveDown(0.5);
        };

        // Header
        doc.fontSize(22).text('User Activity Report', { align: 'center' });
        doc.fontSize(12).fillColor('gray').text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.fillColor('black');
        doc.moveDown();

        // Summary
        addSectionHeader('Summary');
        doc.fontSize(12).text(`Total Activities: ${auditLogs.length}`);
        
        // Activity by user
        const userActivities: Record<string, number> = {};
        auditLogs.forEach(log => {
          const username = log.username || 'Unknown';
          userActivities[username] = (userActivities[username] || 0) + 1;
        });

        // User Activity Chart
        addSectionHeader('Activities by User');
        
        const userChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const userChartBuffer = await userChartCanvas.renderToBuffer({
            type: 'bar',
            data: {
                labels: Object.keys(userActivities),
                datasets: [{
                    label: 'Activities',
                    data: Object.values(userActivities),
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: { display: false },
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        } as any);

        doc.image(userChartBuffer, { width: 450 });
        doc.moveDown();

        // Activity over time
        const activityOverTime: Record<string, number> = {};
        auditLogs.forEach(log => {
          const dateStr = new Date(log.timestamp).toLocaleDateString();
          activityOverTime[dateStr] = (activityOverTime[dateStr] || 0) + 1;
        });

        const timeLabels = Object.keys(activityOverTime).sort();
        const timeData = timeLabels.map(date => activityOverTime[date]);

        addSectionHeader('Activity Over Time');
        
        const timeChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const timeChartBuffer = await timeChartCanvas.renderToBuffer({
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [{
                    label: 'Activities',
                    data: timeData,
                    backgroundColor: 'rgba(255, 99, 132, 0.5)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1,
                    fill: true
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        } as any);

        doc.image(timeChartBuffer, { width: 450 });
        doc.moveDown();

        // Activity by action type
        const actionTypes: Record<string, number> = {};
        auditLogs.forEach(log => {
          const action = log.action || 'Unknown';
          actionTypes[action] = (actionTypes[action] || 0) + 1;
        });

        addSectionHeader('Activities by Action Type');
        
        const actionChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const actionChartBuffer = await actionChartCanvas.renderToBuffer({
            type: 'pie',
            data: {
                labels: Object.keys(actionTypes),
                datasets: [{
                    label: 'Actions',
                    data: Object.values(actionTypes),
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(255, 159, 64, 0.7)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(153, 102, 255, 1)',
                        'rgba(255, 159, 64, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: { display: false },
                    legend: { display: true, position: 'right' }
                }
            }
        } as any);

        doc.image(actionChartBuffer, { width: 450 });
        doc.moveDown();

        // Recent activities
        addSectionHeader('Recent Activities');

        auditLogs.slice(0, 50).forEach((log: any) => {
          doc.fontSize(10).text(`${new Date(log.timestamp).toLocaleString()} - ${log.username || 'Unknown'}: ${log.action}`);
          if (log.targetEntity) {
            doc.fontSize(9).fillColor('gray').text(`  Target: ${log.targetEntity}`);
          }
          if (log.ipAddress) {
            doc.fontSize(9).fillColor('gray').text(`  IP: ${log.ipAddress}`);
          }
          doc.fillColor('black').moveDown(0.3);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private async generateUserActivityExcel(auditLogs: any[], filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const worksheet = workbook.addWorksheet('User Activity');

    // Header
    worksheet.addRow(['User Activity Report']);
    worksheet.addRow(['Generated', new Date().toLocaleString()]);
    worksheet.addRow(['Total Activities', auditLogs.length]);
    worksheet.addRow([]);

    // Activity by User Data
    const userActivities: Record<string, number> = {};
    auditLogs.forEach(log => {
      const username = log.username || 'Unknown';
      userActivities[username] = (userActivities[username] || 0) + 1;
    });

    worksheet.addRow(['Activities by User']);
    worksheet.addRow(['Username', 'Activity Count']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    const userData = Object.entries(userActivities);
    userData.forEach(([username, count]) => {
      worksheet.addRow([username, count]);
    });

    worksheet.addRow([]);

    // Activity by Action Type Data
    const actionTypes: Record<string, number> = {};
    auditLogs.forEach(log => {
      const action = log.action || 'Unknown';
      actionTypes[action] = (actionTypes[action] || 0) + 1;
    });

    worksheet.addRow(['Activities by Action Type']);
    worksheet.addRow(['Action Type', 'Count']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    const actionData = Object.entries(actionTypes);
    actionData.forEach(([action, count]) => {
      worksheet.addRow([action, count]);
    });

    worksheet.addRow([]);

    // Activities
    worksheet.addRow(['Activity Details']);
    worksheet.addRow(['Timestamp', 'Username', 'Action', 'Target Entity', 'IP Address']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    auditLogs.forEach((log: any) => {
      worksheet.addRow([
        new Date(log.timestamp).toLocaleString(),
        log.username || 'Unknown',
        log.action,
        log.targetEntity || 'N/A',
        log.ipAddress || 'N/A'
      ]);
    });

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer as any);
  }

  // Executive Summary Report Generator
  private async generateExecutiveSummaryReport(format: 'pdf' | 'excel', filters: any): Promise<Buffer> {
    const alerts = await this.wazuhService.fetchRecentAlerts({
      severity: filters.severity,
      ip: filters.ip,
      startDate: filters.startDate,
      endDate: filters.endDate,
      limit: 1000,
    });

    const processedAlerts = this.processAlertsForSOC(alerts);

    if (format === 'pdf') {
      return this.generateExecutiveSummaryPdf(processedAlerts, filters);
    } else {
      return this.generateExecutiveSummaryExcel(processedAlerts, filters);
    }
  }

  private async generateExecutiveSummaryPdf(processedData: any, filters: any): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        const addSectionHeader = (title: string) => {
          doc.moveDown();
          doc.fontSize(16).fillColor('#0b192c').text(title, { underline: true });
          doc.fillColor('black').moveDown(0.5);
        };

        // Header
        doc.fontSize(22).text('Executive Summary Report', { align: 'center' });
        doc.fontSize(12).fillColor('gray').text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.fillColor('black');
        doc.moveDown();

        // Key Metrics
        addSectionHeader('Key Security Metrics');
        
        doc.fontSize(12).text(`Total Security Events: ${processedData.totalSecurity}`);
        doc.text(`Total Raw Events: ${processedData.totalRaw}`);
        doc.text(`Noise Filtered: ${processedData.summary.noiseFiltered}`);
        doc.text(`Incidents Detected: ${processedData.incidents.length}`);
        doc.moveDown();

        // Risk Assessment
        addSectionHeader('Risk Assessment');
        
        const highSeverity = processedData.summary.severityDistribution['high'] || 0;
        const mediumSeverity = processedData.summary.severityDistribution['medium'] || 0;
        const riskLevel = highSeverity > 10 ? 'HIGH' : mediumSeverity > 20 ? 'MEDIUM' : 'LOW';
        
        const riskColor = riskLevel === 'HIGH' ? 'red' : riskLevel === 'MEDIUM' ? 'orange' : 'green';
        doc.fontSize(14).fillColor(riskColor).text(`Overall Risk Level: ${riskLevel}`);
        doc.fillColor('black').moveDown();

        // Attack Types Chart
        addSectionHeader('Attack Distribution');
        
        const typeChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const typeChartBuffer = await typeChartCanvas.renderToBuffer({
            type: 'bar',
            data: {
                labels: Object.keys(processedData.summary.attacksByType),
                datasets: [{
                    label: 'Attacks',
                    data: Object.values(processedData.summary.attacksByType),
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: { display: false },
                    legend: { display: false }
                }
            }
        } as any);

        doc.image(typeChartBuffer, { width: 450 });
        doc.moveDown();

        // Alerts Over Time Chart
        addSectionHeader('Security Events Trend');
        
        const timeChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const timeChartBuffer = await timeChartCanvas.renderToBuffer({
            type: 'line',
            data: {
                labels: processedData.summary.alertsOverTime.map((a: any) => new Date(a.time).toLocaleString()),
                datasets: [{
                    label: 'Alert Count',
                    data: processedData.summary.alertsOverTime.map((a: any) => a.count),
                    backgroundColor: 'rgba(255, 99, 132, 0.5)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1,
                    fill: true
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        } as any);

        doc.image(timeChartBuffer, { width: 450 });
        doc.font('Helvetica').moveDown();

        // Top Attack Types
        addSectionHeader('Top Attack Types');

        const attackTypes = Object.entries(processedData.summary.attacksByType)
          .sort((a, b) => (b[1] as number) - (a[1] as number))
          .slice(0, 5);

        attackTypes.forEach(([type, count]) => {
          doc.fontSize(12).text(`• ${type}: ${count} incidents`);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private async generateExecutiveSummaryExcel(processedData: any, filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const worksheet = workbook.addWorksheet('Executive Summary');

    // Header
    worksheet.addRow(['Executive Summary Report']);
    worksheet.addRow(['Generated', new Date().toLocaleString()]);
    worksheet.addRow([]);

    // Key Metrics
    worksheet.addRow(['Key Security Metrics']);
    worksheet.addRow(['Total Security Events', processedData.totalSecurity]);
    worksheet.addRow(['Total Raw Events', processedData.totalRaw]);
    worksheet.addRow(['Noise Filtered', processedData.summary.noiseFiltered]);
    worksheet.addRow(['Incidents Detected', processedData.incidents.length]);
    worksheet.addRow([]);

    // Risk Assessment
    worksheet.addRow(['Risk Assessment']);
    const highSeverity = processedData.summary.severityDistribution['high'] || 0;
    const mediumSeverity = processedData.summary.severityDistribution['medium'] || 0;
    const riskLevel = highSeverity > 10 ? 'HIGH' : mediumSeverity > 20 ? 'MEDIUM' : 'LOW';
    worksheet.addRow(['Overall Risk Level', riskLevel]);
    worksheet.addRow([]);

    // Attack Types Data
    worksheet.addRow(['Attack Types Data']);
    worksheet.addRow(['Attack Type', 'Incidents']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    const attackTypes = Object.entries(processedData.summary.attacksByType)
      .sort((a, b) => (b[1] as number) - (a[1] as number));

    attackTypes.forEach(([type, count]) => {
      worksheet.addRow([type, count]);
    });

    worksheet.addRow([]);

    // Top Attack Types
    worksheet.addRow(['Top Attack Types Summary']);
    worksheet.addRow(['Attack Type', 'Incidents']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    attackTypes.slice(0, 5).forEach(([type, count]) => {
      worksheet.addRow([type, count]);
    });

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer as any);
  }

  // Threat Intelligence Report Generator
  private async generateThreatIntelligenceReport(format: 'pdf' | 'excel', filters: any): Promise<Buffer> {
    const alerts = await this.wazuhService.fetchRecentAlerts({
      severity: filters.severity,
      ip: filters.ip,
      startDate: filters.startDate,
      endDate: filters.endDate,
      limit: 1000,
    });

    const processedAlerts = this.processAlertsForSOC(alerts);

    if (format === 'pdf') {
      return this.generateThreatIntelligencePdf(processedAlerts, filters);
    } else {
      return this.generateThreatIntelligenceExcel(processedAlerts, filters);
    }
  }

  private async generateThreatIntelligencePdf(processedData: any, filters: any): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        const addSectionHeader = (title: string) => {
          doc.moveDown();
          doc.fontSize(16).fillColor('#0b192c').text(title, { underline: true });
          doc.fillColor('black').moveDown(0.5);
        };

        // Header
        doc.fontSize(22).text('Threat Intelligence Report', { align: 'center' });
        doc.fontSize(12).fillColor('gray').text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.fillColor('black');
        doc.moveDown();

        // Attack Patterns Chart
        addSectionHeader('Attack Patterns Distribution');
        
        const attackChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const attackChartBuffer = await attackChartCanvas.renderToBuffer({
            type: 'pie',
            data: {
                labels: Object.keys(processedData.summary.attacksByType),
                datasets: [{
                    label: 'Attacks',
                    data: Object.values(processedData.summary.attacksByType),
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(255, 159, 64, 0.7)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(153, 102, 255, 1)',
                        'rgba(255, 159, 64, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: { display: false },
                    legend: { display: true, position: 'right' }
                }
            }
        } as any);

        doc.image(attackChartBuffer, { width: 450 });
        doc.moveDown();

        // IOCs Detected
        addSectionHeader('Indicators of Compromise (IOCs)');

        const iocs = this.extractIOCs(processedData.rawAlerts);
        
        if (iocs.ips.length > 0) {
          doc.fontSize(14).text('Malicious IP Addresses:');
          iocs.ips.slice(0, 20).forEach((ip: string) => {
            doc.fontSize(11).text(`• ${ip}`);
          });
          doc.moveDown();
        }

        if (iocs.domains.length > 0) {
          doc.fontSize(14).text('Suspicious Domains:');
          iocs.domains.slice(0, 10).forEach((domain: string) => {
            doc.fontSize(11).text(`• ${domain}`);
          });
          doc.moveDown();
        }

        // Geographic Distribution
        addSectionHeader('Geographic Distribution');

        const geoData = this.extractGeoData(processedData.rawAlerts);
        Object.entries(geoData).forEach(([country, count]) => {
          doc.fontSize(12).text(`• ${country}: ${count} alerts`);
        });

        // Attack Patterns List
        doc.moveDown();
        addSectionHeader('Attack Patterns Details');

        Object.entries(processedData.summary.attacksByType).forEach(([type, count]) => {
          doc.fontSize(12).text(`• ${type}: ${count} incidents`);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private async generateThreatIntelligenceExcel(processedData: any, filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const worksheet = workbook.addWorksheet('Threat Intelligence');

    // Header
    worksheet.addRow(['Threat Intelligence Report']);
    worksheet.addRow(['Generated', new Date().toLocaleString()]);
    worksheet.addRow([]);

    // Attack Patterns Data
    worksheet.addRow(['Attack Patterns Data']);
    worksheet.addRow(['Attack Type', 'Incidents']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    const attackTypes = Object.entries(processedData.summary.attacksByType)
      .sort((a, b) => (b[1] as number) - (a[1] as number));

    attackTypes.forEach(([type, count]) => {
      worksheet.addRow([type, count]);
    });

    worksheet.addRow([]);

    // IOCs
    const iocs = this.extractIOCs(processedData.rawAlerts);
    
    worksheet.addRow(['Malicious IP Addresses']);
    iocs.ips.forEach((ip: string) => {
      worksheet.addRow([ip]);
    });
    worksheet.addRow([]);

    worksheet.addRow(['Suspicious Domains']);
    iocs.domains.forEach((domain: string) => {
      worksheet.addRow([domain]);
    });
    worksheet.addRow([]);

    // Geographic Data
    worksheet.addRow(['Geographic Distribution']);
    worksheet.addRow(['Country', 'Alert Count']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    const geoData = this.extractGeoData(processedData.rawAlerts);
    Object.entries(geoData).forEach(([country, count]) => {
      worksheet.addRow([country, count]);
    });

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer as any);
  }

  // Incident Detail Report Generator
  private async generateIncidentDetailReport(format: 'pdf' | 'excel', filters: any): Promise<Buffer> {
    const alerts = await this.wazuhService.fetchRecentAlerts({
      severity: filters.severity,
      ip: filters.ip,
      startDate: filters.startDate,
      endDate: filters.endDate,
      limit: 1000,
    });

    const processedAlerts = this.processAlertsForSOC(alerts);

    if (format === 'pdf') {
      return this.generateIncidentDetailPdf(processedAlerts, filters);
    } else {
      return this.generateIncidentDetailExcel(processedAlerts, filters);
    }
  }

  private async generateIncidentDetailPdf(processedData: any, filters: any): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        const addSectionHeader = (title: string) => {
          doc.moveDown();
          doc.fontSize(16).fillColor('#0b192c').text(title, { underline: true });
          doc.fillColor('black').moveDown(0.5);
        };

        // Header
        doc.fontSize(22).text('Incident Detail Report', { align: 'center' });
        doc.fontSize(12).fillColor('gray').text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.fillColor('black');
        doc.moveDown();

        // Summary
        addSectionHeader('Incident Summary');
        doc.fontSize(12).text(`Total Incidents: ${processedData.incidents.length}`);
        doc.text(`Total Alerts: ${processedData.totalSecurity}`);
        doc.moveDown();

        // Severity Distribution Chart
        addSectionHeader('Severity Distribution');
        
        const severityLabels = Object.keys(processedData.summary.severityDistribution);
        const severityData = Object.values(processedData.summary.severityDistribution);
        
        const severityChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
        const severityChartBuffer = await severityChartCanvas.renderToBuffer({
            type: 'bar',
            data: {
                labels: severityLabels,
                datasets: [{
                    label: 'Incidents by Severity',
                    data: severityData,
                    backgroundColor: severityLabels.map((level: string) => {
                        const lvl = parseInt(level);
                        if (lvl >= 10) return 'rgba(255, 99, 132, 0.7)';
                        if (lvl >= 7) return 'rgba(255, 159, 64, 0.7)';
                        if (lvl >= 5) return 'rgba(255, 206, 86, 0.7)';
                        return 'rgba(75, 192, 192, 0.7)';
                    }),
                    borderColor: severityLabels.map((level: string) => {
                        const lvl = parseInt(level);
                        if (lvl >= 10) return 'rgba(255, 99, 132, 1)';
                        if (lvl >= 7) return 'rgba(255, 159, 64, 1)';
                        if (lvl >= 5) return 'rgba(255, 206, 86, 1)';
                        return 'rgba(75, 192, 192, 1)';
                    }),
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: { display: false },
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        } as any);

        doc.image(severityChartBuffer, { width: 450 });
        doc.moveDown();

        // MITRE ATT&CK Distribution
        addSectionHeader('MITRE ATT&CK Tactics');
        
        const mitreTactics: Record<string, number> = {};
        processedData.incidents.forEach((incident: any) => {
          const tactic = this.mapToMitreTactic(incident);
          if (tactic && tactic !== 'Unknown') {
            mitreTactics[tactic] = (mitreTactics[tactic] || 0) + 1;
          }
        });

        if (Object.keys(mitreTactics).length > 0) {
          const mitreChartCanvas = new ChartJSNodeCanvas({ width: 500, height: 250, backgroundColour: 'white' });
          const mitreChartBuffer = await mitreChartCanvas.renderToBuffer({
              type: 'doughnut',
              data: {
                  labels: Object.keys(mitreTactics),
                  datasets: [{
                      label: 'MITRE Tactics',
                      data: Object.values(mitreTactics),
                      backgroundColor: [
                          'rgba(255, 99, 132, 0.7)',
                          'rgba(54, 162, 235, 0.7)',
                          'rgba(255, 206, 86, 0.7)',
                          'rgba(75, 192, 192, 0.7)',
                          'rgba(153, 102, 255, 0.7)'
                      ],
                      borderColor: [
                          'rgba(255, 99, 132, 1)',
                          'rgba(54, 162, 235, 1)',
                          'rgba(255, 206, 86, 1)',
                          'rgba(75, 192, 192, 1)',
                          'rgba(153, 102, 255, 1)'
                      ],
                      borderWidth: 1
                  }]
              },
              options: {
                  plugins: {
                      title: { display: false },
                      legend: { display: true, position: 'right' }
                  }
              }
          } as any);

          doc.image(mitreChartBuffer, { width: 450 });
          doc.moveDown();
        }

        // Detailed Incidents
        addSectionHeader('Incident Details');

        processedData.incidents.slice(0, 20).forEach((incident: any) => {
          doc.fontSize(12).text(`• ${incident.rule.description}`);
          doc.fontSize(10).fillColor('gray').text(`  Severity: ${incident.rule.level}`);
          doc.text(`  Occurrences: ${incident.count}`);
          doc.text(`  First Seen: ${new Date(incident.firstSeen).toLocaleString()}`);
          doc.text(`  Last Seen: ${new Date(incident.lastSeen).toLocaleString()}`);
          if (incident.data?.src_ip) {
            doc.text(`  Source IP: ${incident.data.src_ip}`);
          }
          if (incident.data?.dest_ip) {
            doc.text(`  Destination IP: ${incident.data.dest_ip}`);
          }
          
          // MITRE ATT&CK mapping (simplified)
          const tactic = this.mapToMitreTactic(incident);
          if (tactic) {
            doc.text(`  MITRE ATT&CK: ${tactic}`);
          }
          
          doc.fillColor('black').moveDown(0.5);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private async generateIncidentDetailExcel(processedData: any, filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const worksheet = workbook.addWorksheet('Incident Details');

    // Header
    worksheet.addRow(['Incident Detail Report']);
    worksheet.addRow(['Generated', new Date().toLocaleString()]);
    worksheet.addRow([]);

    // Severity Distribution Data
    worksheet.addRow(['Severity Distribution']);
    worksheet.addRow(['Severity Level', 'Count']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    const severityData = Object.entries(processedData.summary.severityDistribution);
    severityData.forEach(([level, count]) => {
      worksheet.addRow([level, count]);
    });

    worksheet.addRow([]);

    // MITRE ATT&CK Tactics Data
    const mitreTactics: Record<string, number> = {};
    processedData.incidents.forEach((incident: any) => {
      const tactic = this.mapToMitreTactic(incident);
      if (tactic && tactic !== 'Unknown') {
        mitreTactics[tactic] = (mitreTactics[tactic] || 0) + 1;
      }
    });

    if (Object.keys(mitreTactics).length > 0) {
      worksheet.addRow(['MITRE ATT&CK Tactics']);
      worksheet.addRow(['Tactic', 'Count']);
      worksheet.getRow(worksheet.rowCount).font = { bold: true };

      const mitreData = Object.entries(mitreTactics);
      mitreData.forEach(([tactic, count]) => {
        worksheet.addRow([tactic, count]);
      });

      worksheet.addRow([]);
    }

    // Incidents
    worksheet.addRow(['Incident Details']);
    worksheet.addRow(['Description', 'Severity', 'Occurrences', 'First Seen', 'Last Seen', 'Source IP', 'Destination IP', 'MITRE ATT&CK']);
    worksheet.getRow(worksheet.rowCount).font = { bold: true };

    processedData.incidents.forEach((incident: any) => {
      worksheet.addRow([
        incident.rule.description,
        incident.rule.level,
        incident.count,
        new Date(incident.firstSeen).toLocaleString(),
        new Date(incident.lastSeen).toLocaleString(),
        incident.data?.src_ip || 'N/A',
        incident.data?.dest_ip || 'N/A',
        this.mapToMitreTactic(incident) || 'N/A'
      ]);
    });

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer as any);
  }

  // Helper methods for threat intelligence
  private extractIOCs(alerts: any[]) {
    const ips = new Set<string>();
    const domains = new Set<string>();

    alerts.forEach(alert => {
      if (alert.data?.src_ip) ips.add(alert.data.src_ip);
      if (alert.data?.dest_ip) ips.add(alert.data.dest_ip);
      // Domain extraction would need more sophisticated logic
    });

    return { ips: Array.from(ips), domains: Array.from(domains) };
  }

  private extractGeoData(alerts: any[]) {
    const geoData: Record<string, number> = {};
    
    alerts.forEach(alert => {
      // This would typically use a GeoIP database
      // For now, we'll use a placeholder
      const country = 'Unknown'; // Would be extracted from GeoIP lookup
      geoData[country] = (geoData[country] || 0) + 1;
    });

    return geoData;
  }

  private mapToMitreTactic(incident: any): string {
    // Simplified MITRE ATT&CK mapping based on rule groups
    const groups = incident.rule.groups || [];
    
    if (groups.some(g => g.toLowerCase().includes('authentication'))) return 'Initial Access';
    if (groups.some(g => g.toLowerCase().includes('malware'))) return 'Execution';
    if (groups.some(g => g.toLowerCase().includes('attack'))) return 'Command and Control';
    if (groups.some(g => g.toLowerCase().includes('ids'))) return 'Discovery';
    if (groups.some(g => g.toLowerCase().includes('vulnerability'))) return 'Exploitation';
    
    return 'Unknown';
  }
}
