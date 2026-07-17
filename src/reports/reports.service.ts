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

  async getHistory(): Promise<any[]> {
    const reports = await this.reportRepository.find({
      order: { createdAt: 'DESC' },
    });
    return reports.map((r) => ({
      id: r.id,
      createdBy: r.username ?? '—',
      format: r.format,
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

      // Grouping by type
      const desc = alert.rule.description || '';
      let category = 'Autre (Sécurité)';
      if (desc.includes('SQL Injection')) category = 'SQL Injection';
      else if (desc.includes('SSH')) category = 'SSH Brute Force';
      else if (desc.includes('Shellshock')) category = 'Exploit (Shellshock)';
      else if (desc.includes('sudoers')) category = 'Privilege Escalation';
      else if (desc.includes('port scan') || desc.includes('Nmap')) category = 'Port Scanning';
      else if (desc.includes('File Integrity') || desc.includes('fim')) category = 'FIM Change';

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
      attacksByType,
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
    return new Promise((resolve, reject) => {
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
        Object.entries(summary.attacksByType).forEach(([category, count]) => {
          const percentage = Math.round(((count as number) / Math.max(1, summary.totalSecurityEvents)) * 100);
          const barLength = Math.round(percentage / 2); // max 50 chars
          const bar = '█'.repeat(barLength) + '░'.repeat(50 - barLength);
          doc.fontSize(10).font('Courier').text(`${category.padEnd(25)} ${bar} ${count} (${percentage}%)`);
        });
        doc.moveDown();

        doc.font('Helvetica').fontSize(12).text('Évolution dans le temps:');
        doc.moveDown(0.5);
        summary.alertsOverTime.forEach(({ time, count }: any) => {
          // find max to scale the bar
          const maxCount = Math.max(...summary.alertsOverTime.map((a: any) => a.count), 1);
          const barLength = Math.round((count / maxCount) * 50);
          const bar = '█'.repeat(barLength);
          const displayTime = new Date(time).toLocaleString();
          doc.fontSize(10).font('Courier').text(`${displayTime.padEnd(22)} | ${bar} ${count}`);
        });
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
}
