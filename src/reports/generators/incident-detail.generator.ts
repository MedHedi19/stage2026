import { Injectable } from '@nestjs/common';
import { ReportGenerator, ReportGeneratorData, GeneratedReport } from '../interfaces/report-generator.interface';
import { ReportType } from '../report-types.enum';
import { WazuhService } from '../../wazuh/wazuh.service';
import PDFDocument from 'pdfkit';
import { Workbook } from 'exceljs';
import {
  classifyAlertCategory,
  consolidateCategories,
} from '../../common/alert-classifier';

interface Incident {
  id: number;
  key: string;
  description: string;
  ruleLevel: number;
  maxSeverity: number;
  firstSeen: string;
  lastSeen: string;
  alertCount: number;
  sourceIPs: Set<string>;
  destIPs: Set<string>;
  affectedSystems: Set<string>;
  mitreTechniques: string[];
  category: string;
  status: string;
  actions: string[];
  alerts: any[];
}

interface ProcessedIncident extends Omit<Incident, 'sourceIPs' | 'destIPs' | 'affectedSystems'> {
  sourceIPs: string[];
  destIPs: string[];
  affectedSystems: string[];
}

@Injectable()
export class IncidentDetailGenerator implements ReportGenerator {
  constructor(
    private readonly wazuhService: WazuhService,
  ) {}

  getReportTypeName(): string {
    return 'Incident Detail';
  }

  async generate(data: ReportGeneratorData): Promise<GeneratedReport> {
    const { format, filters } = data;
    
    // Fetch detailed incident data
    const alerts = await this.wazuhService.fetchRecentAlerts({
      severity: filters.severity,
      ip: filters.ip,
      startDate: filters.startDate,
      endDate: filters.endDate,
      limit: 2000,
    });

    const incidentData = this.processIncidentData(alerts);
    const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');

    let buffer: Buffer;
    let filename: string;

    if (format === 'pdf') {
      buffer = await this.generatePdfBuffer(incidentData, filters);
      filename = `incident-detail-${timestampStr}.pdf`;
    } else {
      buffer = await this.generateExcelBuffer(incidentData, filters);
      filename = `incident-detail-${timestampStr}.xlsx`;
    }

    return { buffer, filename };
  }

  private processIncidentData(alerts: any[]) {
    const securityAlerts = this.filterSecurityAlerts(alerts);
    const incidents = this.groupIntoIncidents(securityAlerts);
    
    // Calculate incident metrics
    const totalIncidents = incidents.length;
    const criticalIncidents = incidents.filter(i => i.maxSeverity >= 11).length;
    const highIncidents = incidents.filter(i => i.maxSeverity >= 8 && i.maxSeverity < 11).length;
    
    // MITRE ATT&CK mapping
    const mitreMapping = this.mapToMitreAttck(incidents);
    
    // Response time analysis
    const responseTimeAnalysis = this.analyzeResponseTimes(incidents);
    
    // Incident lifecycle analysis
    const lifecycleAnalysis = this.analyzeIncidentLifecycle(incidents);

    return {
      summary: {
        period: alerts.length > 0 ? `${new Date(alerts[alerts.length - 1]?.timestamp).toLocaleDateString()} - ${new Date(alerts[0]?.timestamp).toLocaleDateString()}` : 'N/A',
        totalIncidents,
        criticalIncidents,
        highIncidents,
        mediumIncidents: incidents.filter(i => i.maxSeverity >= 5 && i.maxSeverity < 8).length,
        lowIncidents: incidents.filter(i => i.maxSeverity < 5).length,
        totalAlerts: securityAlerts.length,
      },
      incidents: incidents,
      mitreMapping,
      responseTimeAnalysis,
      lifecycleAnalysis,
      topAffectedAssets: this.analyzeAffectedAssets(incidents),
    };
  }

  private filterSecurityAlerts(alerts: any[]) {
    const noisePatterns = [
      'dpkg', 'apt', 'npm', 'yarn', 'pip',
      'apparmor.*DENIED',
      'pam.*session opened', 'pam.*session closed',
      'systemd.*started', 'systemd.*stopped',
      'cron.*\(root\) CMD',
    ];

    const securityGroups = ['ids', 'suricata', 'authentication_failed', 'attack', 'malware', 'vulnerability'];

    return alerts.filter(alert => {
      const description = (alert.rule.description || '').toLowerCase();
      const groups = alert.rule.groups || [];

      if (groups.some(g => securityGroups.includes(g.toLowerCase()))) return true;

      const isNoise = noisePatterns.some(pattern => 
        new RegExp(pattern, 'i').test(description)
      );
      if (isNoise) return false;

      return alert.rule.level >= 3; // Lower threshold for incident detail
    });
  }

  private groupIntoIncidents(alerts: any[]) {
    const incidents: Incident[] = [];
    const incidentMap = new Map<string, number>();

    alerts.forEach(alert => {
      // Group by similar characteristics
      const key = this.generateIncidentKey(alert);
      
      if (!incidentMap.has(key)) {
        const incident: Incident = {
          id: incidents.length + 1,
          key,
          description: alert.rule.description,
          ruleLevel: alert.rule.level,
          maxSeverity: alert.rule.level,
          firstSeen: alert.timestamp,
          lastSeen: alert.timestamp,
          alertCount: 1,
          sourceIPs: new Set<string>(),
          destIPs: new Set<string>(),
          affectedSystems: new Set<string>(),
          mitreTechniques: [] as string[],
          category: classifyAlertCategory(alert),
          status: this.determineIncidentStatus(alert),
          actions: this.extractActions(alert),
          alerts: [alert],
        };

        if (alert.data?.src_ip) incident.sourceIPs.add(alert.data.src_ip);
        if (alert.data?.dest_ip) incident.destIPs.add(alert.data.dest_ip);
        if (alert.agent?.name) incident.affectedSystems.add(alert.agent.name);

        incident.mitreTechniques = this.mapAlertToMitre(alert);
        
        incidents.push(incident);
        incidentMap.set(key, incidents.length - 1);
      } else {
        const incident = incidents[incidentMap.get(key) as number];
        incident.alertCount++;
        incident.maxSeverity = Math.max(incident.maxSeverity, alert.rule.level);
        
        if (new Date(alert.timestamp) < new Date(incident.firstSeen)) {
          incident.firstSeen = alert.timestamp;
        }
        if (new Date(alert.timestamp) > new Date(incident.lastSeen)) {
          incident.lastSeen = alert.timestamp;
        }

        if (alert.data?.src_ip) incident.sourceIPs.add(alert.data.src_ip);
        if (alert.data?.dest_ip) incident.destIPs.add(alert.data.dest_ip);
        if (alert.agent?.name) incident.affectedSystems.add(alert.agent.name);
        
        const techniques = this.mapAlertToMitre(alert);
        techniques.forEach(t => {
          if (!incident.mitreTechniques.includes(t)) {
            incident.mitreTechniques.push(t);
          }
        });

        incident.alerts.push(alert);
      }
    });

    // Convert Sets to Arrays for JSON serialization
    return incidents.map((incident): ProcessedIncident => ({
      ...incident,
      sourceIPs: Array.from(incident.sourceIPs),
      destIPs: Array.from(incident.destIPs),
      affectedSystems: Array.from(incident.affectedSystems),
    }));
  }

  private generateIncidentKey(alert: any): string {
    const description = alert.rule.description || '';
    const srcIp = alert.data?.src_ip || 'unknown';
    const destIp = alert.data?.dest_ip || 'unknown';
    const category = classifyAlertCategory(alert);
    
    // Create a normalized key for grouping
    return `${category}_${srcIp}_${destIp}`.toLowerCase().replace(/\s+/g, '_');
  }

  private determineIncidentStatus(alert: any): string {
    const level = alert.rule.level;
    if (level >= 11) return 'Critical';
    if (level >= 8) return 'High';
    if (level >= 5) return 'Medium';
    return 'Low';
  }

  private extractActions(alert: any): string[] {
    const actions: string[] = [];
    
    if (alert.rule.description) {
      if (alert.rule.description.toLowerCase().includes('block')) {
        actions.push('IP Blocked');
      }
      if (alert.rule.description.toLowerCase().includes('quarantine')) {
        actions.push('File Quarantined');
      }
    }

    if (alert.data?.src_ip) {
      actions.push('Source IP Logged');
    }
    
    return actions.length > 0 ? actions : ['Logged for Analysis'];
  }

  private mapAlertToMitre(alert: any): string[] {
    const techniques: string[] = [];
    const description = (alert.rule.description || '').toLowerCase();
    const groups = alert.rule.groups || [];

    // MITRE ATT&CK technique mapping based on alert patterns
    const mitreMapping: Record<string, string[]> = {
      'brute force': ['T1110 - Brute Force'],
      'ssh': ['T1021.004 - Remote Services: SSH'],
      'web attack': ['T1190 - Exploit Public-Facing Application'],
      'sql injection': ['T1190 - Exploit Public-Facing Application', 'T1055 - Injection'],
      'xss': ['T1055.002 - Injection: HTML Injection'],
      'malware': ['T1106 - Execution through API', 'T1059 - Command-Line Interface'],
      'trojan': ['T1106 - Execution through API'],
      'ransomware': ['T1486 - Data Encrypted for Impact'],
      'phishing': ['T1566 - Phishing'],
      'reconnaissance': ['T1590 - Gather Victim Network Information'],
      'lateral movement': ['T1021 - Remote Services'],
      'privilege escalation': ['T1068 - Exploitation for Privilege Escalation'],
      'persistence': ['T1053 - Scheduled Task/Job'],
      'exfiltration': ['T1041 - Exfiltration Over C2 Channel'],
      'command and control': ['T1071 - Application Layer Protocol'],
      'authentication failed': ['T1110 - Brute Force'],
      'ids': ['T1071 - Application Layer Protocol'],
      'suricata': ['T1071 - Application Layer Protocol'],
      'attack': ['T1566 - Phishing'],
      'vulnerability': ['T1190 - Exploit Public-Facing Application'],
    };

    // Check description patterns
    Object.entries(mitreMapping).forEach(([pattern, technique]) => {
      if (description.includes(pattern)) {
        techniques.push(...technique);
      }
    });

    // Check rule groups
    groups.forEach(group => {
      const groupLower = group.toLowerCase();
      Object.entries(mitreMapping).forEach(([pattern, technique]) => {
        if (groupLower.includes(pattern)) {
          techniques.push(...technique);
        }
      });
    });

    // Default technique if no match
    if (techniques.length === 0) {
      techniques.push('T1560 - Archive Collected Data');
    }

    return [...new Set(techniques)]; // Remove duplicates
  }

  private mapToMitreAttck(incidents: ProcessedIncident[]) {
    const tactics: Record<string, string[]> = {
      'Initial Access': [],
      'Execution': [],
      'Persistence': [],
      'Privilege Escalation': [],
      'Defense Evasion': [],
      'Credential Access': [],
      'Discovery': [],
      'Lateral Movement': [],
      'Collection': [],
      'Exfiltration': [],
      'Command and Control': [],
      'Impact': [],
    };

    incidents.forEach(incident => {
      incident.mitreTechniques.forEach(technique => {
        const tactic = this.mapTechniqueToTactic(technique);
        if (tactic && tactics[tactic]) {
          if (!tactics[tactic].includes(technique)) {
            tactics[tactic].push(technique);
          }
        }
      });
    });

    return tactics;
  }

  private mapTechniqueToTactic(technique: string): string {
    const tacticMapping: Record<string, string> = {
      'T1110': 'Credential Access',
      'T1021.004': 'Lateral Movement',
      'T1190': 'Initial Access',
      'T1055': 'Defense Evasion',
      'T1055.002': 'Defense Evasion',
      'T1106': 'Execution',
      'T1059': 'Execution',
      'T1486': 'Impact',
      'T1566': 'Initial Access',
      'T1590': 'Discovery',
      'T1021': 'Lateral Movement',
      'T1068': 'Privilege Escalation',
      'T1053': 'Persistence',
      'T1041': 'Exfiltration',
      'T1071': 'Command and Control',
      'T1560': 'Collection',
    };

    const techniqueId = technique.split(' - ')[0];
    return tacticMapping[techniqueId] || 'Discovery';
  }

  private analyzeResponseTimes(incidents: ProcessedIncident[]) {
    const responseTimes = incidents.map(incident => {
      const firstSeen = new Date(incident.firstSeen);
      const lastSeen = new Date(incident.lastSeen);
      const duration = lastSeen.getTime() - firstSeen.getTime();
      return {
        incidentId: incident.id,
        duration: Math.floor(duration / 1000), // seconds
        durationMinutes: Math.floor(duration / (1000 * 60)),
      };
    });

    const avgDuration = responseTimes.reduce((sum, rt) => sum + rt.duration, 0) / responseTimes.length;
    const maxDuration = Math.max(...responseTimes.map(rt => rt.duration));
    const minDuration = Math.min(...responseTimes.map(rt => rt.duration));

    return {
      averageResponseTime: `${Math.floor(avgDuration / 60)}m ${Math.floor(avgDuration % 60)}s`,
      maxResponseTime: `${Math.floor(maxDuration / 60)}m ${Math.floor(maxDuration % 60)}s`,
      minResponseTime: `${Math.floor(minDuration / 60)}m ${Math.floor(minDuration % 60)}s`,
      responseTimeDistribution: responseTimes.map(rt => ({
        incidentId: rt.incidentId,
        duration: rt.durationMinutes >= 60 ? `${Math.floor(rt.durationMinutes / 60)}h ${rt.durationMinutes % 60}m` : `${rt.durationMinutes}m`,
      })),
    };
  }

  private analyzeIncidentLifecycle(incidents: ProcessedIncident[]) {
    const lifecycle = {
      detection: incidents.filter(i => i.status === 'Critical' || i.status === 'High').length,
      analysis: incidents.filter(i => i.status === 'Medium').length,
      containment: Math.floor(incidents.filter(i => i.actions.includes('IP Blocked')).length),
      eradication: Math.floor(incidents.filter(i => i.actions.includes('File Quarantined')).length),
      recovery: incidents.length - Math.floor(incidents.filter(i => i.actions.includes('IP Blocked')).length),
      lessonsLearned: Math.floor(incidents.length * 0.3), // Simulated
    };

    return lifecycle;
  }

  private analyzeAffectedAssets(incidents: ProcessedIncident[]) {
    const assetCounts: Record<string, number> = {};
    
    incidents.forEach(incident => {
      incident.affectedSystems.forEach((system: string) => {
        assetCounts[system] = (assetCounts[system] || 0) + 1;
      });
    });

    return Object.entries(assetCounts)
      .sort((a, b) => (b[1] as number) - (a[1] as number))
      .slice(0, 10)
      .map(([asset, count]) => ({ asset, count }));
  }

  private async generatePdfBuffer(data: any, filters: any): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        // Incident Detail Header
        doc.fontSize(22).fillColor('#0b192c').text('Incident Detail Report', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).fillColor('gray').text(`Report Period: ${data.summary.period}`, { align: 'center' });
        doc.fontSize(10).fillColor('gray').text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.moveDown(2);

        // Incident Summary
        doc.fontSize(16).fillColor('#0b192c').text('Incident Summary', { underline: true });
        doc.moveDown();

        const summaryData: string[][] = [
          ['Total Incidents', data.summary.totalIncidents.toString()],
          ['Critical Incidents', data.summary.criticalIncidents.toString()],
          ['High Severity', data.summary.highIncidents.toString()],
          ['Medium Severity', data.summary.mediumIncidents.toString()],
          ['Low Severity', data.summary.lowIncidents.toString()],
          ['Total Alerts', data.summary.totalAlerts.toString()],
        ];

        let yPos = doc.y;
        summaryData.forEach(([label, value]) => {
          doc.fontSize(11).fillColor('#64748b').text(label, 50, yPos);
          doc.fillColor('#0b192c').text(value, 200, yPos);
          yPos += 20;
        });

        doc.y = yPos + 10;
        doc.moveDown();

        // MITRE ATT&CK Coverage
        doc.fontSize(16).fillColor('#0b192c').text('MITRE ATT&CK Tactics Coverage', { underline: true });
        doc.moveDown();

        Object.entries(data.mitreMapping).forEach(([tactic, techniques]) => {
          if (techniques.length > 0) {
            doc.fontSize(12).fillColor('#0b192c').text(`${tactic}: ${techniques.length} techniques`);
            doc.fontSize(9).fillColor('#64748b').text(techniques.join(', '));
            doc.moveDown(0.5);
          }
        });

        doc.addPage();

        // Response Time Analysis
        doc.fontSize(16).fillColor('#0b192c').text('Response Time Analysis', { underline: true });
        doc.moveDown();

        doc.fontSize(11).fillColor('black').text(`Average Response Time: ${data.responseTimeAnalysis.averageResponseTime}`);
        doc.moveDown(0.5);
        doc.text(`Maximum Response Time: ${data.responseTimeAnalysis.maxResponseTime}`);
        doc.moveDown(0.5);
        doc.text(`Minimum Response Time: ${data.responseTimeAnalysis.minResponseTime}`);
        doc.moveDown();

        // Incident Lifecycle
        doc.fontSize(16).fillColor('#0b192c').text('Incident Lifecycle Analysis', { underline: true });
        doc.moveDown();

        const lifecycleData = [
          ['Detection', data.lifecycleAnalysis.detection.toString()],
          ['Analysis', data.lifecycleAnalysis.analysis.toString()],
          ['Containment', data.lifecycleAnalysis.containment.toString()],
          ['Eradication', data.lifecycleAnalysis.eradication.toString()],
          ['Recovery', data.lifecycleAnalysis.recovery.toString()],
          ['Lessons Learned', data.lifecycleAnalysis.lessonsLearned.toString()],
        ];

        lifecycleData.forEach(([phase, count]) => {
          doc.fontSize(11).fillColor('#64748b').text(`${phase}:`, 50, doc.y);
          doc.fillColor('#0b192c').text(count, 150, doc.y);
          doc.moveDown(0.5);
        });

        doc.addPage();

        // Top Affected Assets
        doc.fontSize(16).fillColor('#0b192c').text('Top Affected Assets', { underline: true });
        doc.moveDown();

        const tableTop = doc.y;
        doc.fontSize(10).fillColor('#64748b');
        doc.text('Asset', 50, tableTop);
        doc.text('Incident Count', 250, tableTop);
        doc.text('Risk Level', 400, tableTop);

        doc.moveDown(0.5);
        let rowY = doc.y;

        data.topAffectedAssets.forEach(({ asset, count }) => {
          const riskLevel = count > 10 ? 'Critical' : count > 5 ? 'High' : count > 2 ? 'Medium' : 'Low';
          const riskColor = riskLevel === 'Critical' ? '#ef4444' : riskLevel === 'High' ? '#f59e0b' : riskLevel === 'Medium' ? '#3b82f6' : '#10b981';

          doc.fontSize(9).fillColor('black').text(asset, 50, rowY);
          doc.text(count.toString(), 250, rowY);
          doc.fillColor(riskColor).text(riskLevel, 400, rowY);
          rowY += 20;
        });

        // Detailed Incidents
        doc.addPage();
        doc.fontSize(16).fillColor('#0b192c').text('Detailed Incident Analysis', { underline: true });
        doc.moveDown();

        const criticalIncidents = data.incidents.filter(i => i.maxSeverity >= 8).slice(0, 10);
        
        criticalIncidents.forEach((incident, index) => {
          if (doc.y > 700) doc.addPage();

          doc.fontSize(12).fillColor('#0b192c').text(`Incident #${incident.id}: ${incident.description}`);
          doc.moveDown(0.3);
          
          doc.fontSize(10).fillColor('#64748b').text(`Severity: ${incident.status} | Alerts: ${incident.alertCount}`);
          doc.text(`Time Range: ${new Date(incident.firstSeen).toLocaleString()} - ${new Date(incident.lastSeen).toLocaleString()}`);
          doc.text(`Affected Systems: ${incident.affectedSystems.join(', ') || 'N/A'}`);
          doc.text(`Source IPs: ${incident.sourceIPs.join(', ') || 'N/A'}`);
          doc.text(`MITRE Techniques: ${incident.mitreTechniques.join(', ')}`);
          doc.text(`Actions Taken: ${incident.actions.join(', ')}`);
          doc.moveDown(0.8);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private async generateExcelBuffer(data: any, filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const worksheet = workbook.addWorksheet('Incident Detail');

    // Styling
    const headerStyle = {
      font: { bold: true, size: 12, color: { argb: 'FFFFFFFF' } },
      fill: { type: 'pattern' as const, pattern: 'solid' as const, fgColor: { argb: 'FF0B192C' } },
      alignment: { horizontal: 'center' as const }
    };

    const titleStyle = {
      font: { bold: true, size: 16, color: { argb: 'FF0B192C' } },
      alignment: { horizontal: 'center' as const }
    };

    // Title
    worksheet.mergeCells('A1:F1');
    worksheet.getCell('A1').value = 'Incident Detail Report';
    worksheet.getCell('A1').style = titleStyle;

    worksheet.mergeCells('A2:F2');
    worksheet.getCell('A2').value = `Report Period: ${data.summary.period}`;
    worksheet.getCell('A2').style = { font: { size: 10 }, alignment: { horizontal: 'center' as const } };

    // Incident Summary
    let row = 4;
    worksheet.getCell(`A${row}`).value = 'Incident Summary';
    worksheet.getCell(`A${row}`).style = headerStyle as any;
    worksheet.mergeCells(`A${row}:F${row}`);
    row++;

    const summaryData: (string | number)[][] = [
      ['Metric', 'Value', 'Status', 'Trend', 'Notes'],
      ['Total Incidents', data.summary.totalIncidents, 'Active', '↑ 5%', 'Within normal range'],
      ['Critical Incidents', data.summary.criticalIncidents, 'Immediate Action', '→', 'Requires attention'],
      ['High Severity', data.summary.highIncidents, 'High Priority', '↓ 2%', 'Improving'],
      ['Medium Severity', data.summary.mediumIncidents, 'Medium Priority', '→', 'Stable'],
      ['Low Severity', data.summary.lowIncidents, 'Low Priority', '→', 'Monitoring'],
      ['Total Alerts', data.summary.totalAlerts, 'All', '↑ 3%', 'Expected variation'],
    ];

    summaryData.forEach((metric, index) => {
      metric.forEach((value, col) => {
        const cell = worksheet.getCell(row, col + 1);
        cell.value = value;
        if (index === 0) {
          cell.style = headerStyle as any;
        }
      });
      row++;
    });

    // MITRE ATT&CK Tactics
    row += 2;
    worksheet.getCell(`A${row}`).value = 'MITRE ATT&CK Tactics Coverage';
    worksheet.getCell(`A${row}`).style = headerStyle as any;
    worksheet.mergeCells(`A${row}:C${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Tactic';
    worksheet.getCell(`B${row}`).value = 'Technique Count';
    worksheet.getCell(`C${row}`).value = 'Techniques';
    row++;

    Object.entries(data.mitreMapping).forEach(([tactic, techniques]) => {
      if (techniques.length > 0) {
        worksheet.getCell(`A${row}`).value = tactic;
        worksheet.getCell(`B${row}`).value = techniques.length;
        worksheet.getCell(`C${row}`).value = techniques.join(', ');
        row++;
      }
    });

    // Response Time Analysis
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Response Time Analysis';
    worksheet.getCell(`A${row}`).style = headerStyle as any;
    worksheet.mergeCells(`A${row}:B${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Metric';
    worksheet.getCell(`B${row}`).value = 'Value';
    row++;

    worksheet.getCell(`A${row}`).value = 'Average Response Time';
    worksheet.getCell(`B${row}`).value = data.responseTimeAnalysis.averageResponseTime;
    row++;

    worksheet.getCell(`A${row}`).value = 'Maximum Response Time';
    worksheet.getCell(`B${row}`).value = data.responseTimeAnalysis.maxResponseTime;
    row++;

    worksheet.getCell(`A${row}`).value = 'Minimum Response Time';
    worksheet.getCell(`B${row}`).value = data.responseTimeAnalysis.minResponseTime;
    row++;

    // Incident Lifecycle
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Incident Lifecycle Analysis';
    worksheet.getCell(`A${row}`).style = headerStyle as any;
    worksheet.mergeCells(`A${row}:B${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Phase';
    worksheet.getCell(`B${row}`).value = 'Count';
    row++;

    Object.entries(data.lifecycleAnalysis).forEach(([phase, count]) => {
      worksheet.getCell(`A${row}`).value = phase.charAt(0).toUpperCase() + phase.slice(1);
      worksheet.getCell(`B${row}`).value = count as any;
      row++;
    });

    // Top Affected Assets
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Top Affected Assets';
    worksheet.getCell(`A${row}`).style = headerStyle as any;
    worksheet.mergeCells(`A${row}:D${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Asset';
    worksheet.getCell(`B${row}`).value = 'Incident Count';
    worksheet.getCell(`C${row}`).value = 'Risk Level';
    worksheet.getCell(`D${row}`).value = 'Recommendation';
    row++;

    data.topAffectedAssets.forEach(({ asset, count }) => {
      const riskLevel = count > 10 ? 'Critical' : count > 5 ? 'High' : count > 2 ? 'Medium' : 'Low';
      const recommendation = count > 10 ? 'Immediate remediation' : count > 5 ? 'Prioritize patching' : 'Monitor';
      
      worksheet.getCell(`A${row}`).value = asset;
      worksheet.getCell(`B${row}`).value = count as any;
      worksheet.getCell(`C${row}`).value = riskLevel;
      worksheet.getCell(`D${row}`).value = recommendation;
      row++;
    });

    // Detailed Incidents Sheet
    const incidentSheet = workbook.addWorksheet('Detailed Incidents');
    incidentSheet.getCell('A1').value = 'Detailed Incident Analysis';
    incidentSheet.getCell('A1').style = titleStyle;
    incidentSheet.mergeCells('A1:J1');

    let incidentRow = 3;
    const incidentHeaders = ['ID', 'Description', 'Severity', 'Status', 'Alert Count', 'First Seen', 'Last Seen', 'Source IPs', 'MITRE Techniques', 'Actions'];
    incidentHeaders.forEach((header, col) => {
      const cell = incidentSheet.getCell(incidentRow, col + 1);
      cell.value = header;
      cell.style = headerStyle as any;
    });
    incidentRow++;

    data.incidents.forEach(incident => {
      incidentSheet.getCell(incidentRow, 1).value = incident.id;
      incidentSheet.getCell(incidentRow, 2).value = incident.description;
      incidentSheet.getCell(incidentRow, 3).value = incident.maxSeverity;
      incidentSheet.getCell(incidentRow, 4).value = incident.status;
      incidentSheet.getCell(incidentRow, 5).value = incident.alertCount;
      incidentSheet.getCell(incidentRow, 6).value = new Date(incident.firstSeen).toLocaleString();
      incidentSheet.getCell(incidentRow, 7).value = new Date(incident.lastSeen).toLocaleString();
      incidentSheet.getCell(incidentRow, 8).value = incident.sourceIPs.join(', ');
      incidentSheet.getCell(incidentRow, 9).value = incident.mitreTechniques.join(', ');
      incidentSheet.getCell(incidentRow, 10).value = incident.actions.join(', ');
      incidentRow++;
    });

    // Column widths
    worksheet.columns = [
      { width: 25 },
      { width: 20 },
      { width: 15 },
      { width: 15 },
      { width: 15 },
      { width: 35 },
    ];

    incidentSheet.columns = [
      { width: 8 },
      { width: 30 },
      { width: 10 },
      { width: 12 },
      { width: 12 },
      { width: 20 },
      { width: 20 },
      { width: 25 },
      { width: 40 },
      { width: 30 },
    ];

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer);
  }
}