import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Report } from './entities/report.entity';
import { WazuhService } from '../wazuh/wazuh.service';
import * as PDFDocument from 'pdfkit';
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

    // 2. Generate appropriate document buffer
    let buffer: Buffer;
    let filename: string;
    const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');

    if (format === 'pdf') {
      buffer = await this.generatePdfBuffer(alerts, filters);
      filename = `security-report-${timestampStr}.pdf`;
    } else {
      buffer = await this.generateExcelBuffer(alerts, filters);
      filename = `security-report-${timestampStr}.xlsx`;
    }

    // 3. Insert metadata record in MySQL database
    const report = this.reportRepository.create({
      userId,
      username,
      format,
      filters: JSON.stringify(filters),
    });
    await this.reportRepository.save(report);

    return { buffer, filename };
  }

  async getHistory(): Promise<Report[]> {
    return this.reportRepository.find({
      order: {
        createdAt: 'DESC',
      },
    });
  }

  private async generatePdfBuffer(alerts: any[], filters: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new (PDFDocument as any)({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        // Document Header
        doc.rect(0, 0, doc.page.width, 100).fill('#0B192C');
        doc.fillColor('#FFFFFF')
           .fontSize(22)
           .text('IDS/IPS CYBERSECURITY DASHBOARD REPORT', 40, 30, { bold: true } as any);
        doc.fontSize(10)
           .text(`Date: ${new Date().toLocaleString()} | System Administrator Report`, 40, 60);

        doc.fillColor('#333333');
        doc.moveDown(4);

        // Parameters summary
        doc.fontSize(12).text('Report Context', { underline: true } as any);
        doc.fontSize(10).text(`Filters Applied: ${JSON.stringify(filters)}`);
        doc.text(`Total Alerts Processed: ${alerts.length}`);
        doc.moveDown();

        doc.fontSize(12).text('Threat Incident List', { underline: true } as any);
        doc.moveDown(0.5);

        // Alerts loop
        alerts.forEach((alert, index) => {
          // If we reach near end of page, add page
          if (doc.y > 680) {
            doc.addPage();
          }

          doc.rect(40, doc.y, doc.page.width - 80, 50).fillAndStroke('#F1F6F9', '#D9E4EC');
          
          doc.fillColor('#D80032')
             .fontSize(10)
             .text(`[LVL ${alert.rule.level}] ${alert.rule.description}`, 50, doc.y - 45, { bold: true } as any);

          doc.fillColor('#333333')
             .fontSize(8)
             .text(`Time: ${alert.timestamp}  |  Host: ${alert.agent.name} (IP: ${alert.agent.ip || 'N/A'})`, 50, doc.y - 30);
          
          doc.text(`Source IP: ${alert.data.src_ip || 'N/A'}  -->  Destination IP: ${alert.data.dest_ip || 'N/A'}  |  Proto: ${alert.data.protocol || 'N/A'}`, 50, doc.y - 18);
          
          doc.moveDown(1.5);
        });

        doc.end();
      } catch (err) {
        reject(err);
      }
    });
  }

  private async generateExcelBuffer(alerts: any[], filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const worksheet = workbook.addWorksheet('Incident Reports');

    worksheet.addRow(['IDS/IPS Cybersecurity Alert Report']);
    worksheet.addRow([`Report Generated On: ${new Date().toLocaleString()}`]);
    worksheet.addRow([`Filters: ${JSON.stringify(filters)}`]);
    worksheet.addRow([]); // Blank row

    worksheet.getRow(1).font = { size: 16, bold: true };
    worksheet.getRow(2).font = { italic: true };

    // Columns
    worksheet.columns = [
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
    ];

    alerts.forEach(alert => {
      worksheet.addRow({
        id: alert.id,
        timestamp: alert.timestamp,
        level: alert.rule.level,
        ruleId: alert.rule.id,
        description: alert.rule.description,
        agentId: alert.agent.id,
        agentName: alert.agent.name,
        srcIp: alert.data.src_ip || 'N/A',
        destIp: alert.data.dest_ip || 'N/A',
        protocol: alert.data.protocol || 'N/A',
      });
    });

    // Style column header row (which is row 5, since we added 4 rows at top)
    const headerRowIdx = 5;
    const headerRow = worksheet.getRow(headerRowIdx);
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
