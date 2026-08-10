import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import PDFDocument from 'pdfkit';
import { Workbook } from 'exceljs';
import { WazuhService } from '../../wazuh/wazuh.service';
import { BlacklistEntry } from '../../firewall/entities/blacklist-entry.entity';
import { WhitelistEntry } from '../../firewall/entities/whitelist-entry.entity';
import { GeneratedReport, ReportGenerator, ReportGeneratorData } from '../interfaces/report-generator.interface';

type ListRow = { list: 'Blacklist' | 'Whitelist'; ip: string; reason: string; addedBy: string; addedAt: Date; events: number; bytes: number };

@Injectable()
export class FirewallListTrafficGenerator implements ReportGenerator {
  constructor(
    private readonly wazuhService: WazuhService,
    @InjectRepository(BlacklistEntry) private readonly blacklistRepository: Repository<BlacklistEntry>,
    @InjectRepository(WhitelistEntry) private readonly whitelistRepository: Repository<WhitelistEntry>,
  ) {}

  getReportTypeName() { return 'Firewall List Traffic'; }

  async generate({ format, filters }: ReportGeneratorData): Promise<GeneratedReport> {
    const [blacklist, whitelist, alerts] = await Promise.all([
      this.blacklistRepository.find({ where: { active: true }, order: { createdAt: 'DESC' } }),
      this.whitelistRepository.find({ order: { createdAt: 'DESC' } }),
      this.wazuhService.fetchRecentAlerts({ startDate: filters.startDate, endDate: filters.endDate, limit: 5000 }),
    ]);
    const rows = this.buildRows(blacklist, whitelist, alerts);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const buffer = format === 'excel' ? await this.excel(rows, filters) : await this.pdf(rows, filters);
    return { buffer, filename: `firewall-list-traffic-${stamp}.${format === 'excel' ? 'xlsx' : 'pdf'}` };
  }

  private buildRows(blacklist: BlacklistEntry[], whitelist: WhitelistEntry[], alerts: any[]): ListRow[] {
    const stats = new Map<string, { events: number; bytes: number }>();
    for (const alert of alerts) {
      const ip = alert?.data?.src_ip || alert?.data?.dst_ip || alert?.data?.dest_ip;
      if (!ip) continue;
      const current = stats.get(ip) || { events: 0, bytes: 0 };
      current.events += 1;
      current.bytes += this.extractBytes(alert);
      stats.set(ip, current);
    }
    const mapEntry = (entry: any, list: ListRow['list']): ListRow => ({
      list, ip: entry.ip, reason: entry.reason || 'Not specified', addedBy: entry.addedBy || 'System', addedAt: entry.createdAt,
      events: stats.get(entry.ip)?.events || 0, bytes: stats.get(entry.ip)?.bytes || 0,
    });
    return [...blacklist.map((entry) => mapEntry(entry, 'Blacklist')), ...whitelist.map((entry) => mapEntry(entry, 'Whitelist'))]
      .sort((a, b) => a.list.localeCompare(b.list) || b.events - a.events);
  }

  private extractBytes(alert: any): number {
    const values = [alert?.data?.bytes, alert?.data?.src_bytes, alert?.data?.dest_bytes, alert?.data?.flow?.bytes, alert?.data?.network?.bytes];
    return values.reduce((sum, value) => sum + (Number.isFinite(Number(value)) ? Number(value) : 0), 0);
  }

  private formatBytes(bytes: number) {
    if (!bytes) return 'No byte data';
    const units = ['B', 'KB', 'MB', 'GB']; let value = bytes; let index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
    return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  private async pdf(rows: ListRow[], filters: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 42, size: 'A4' }); const chunks: Buffer[] = [];
      doc.on('data', (chunk) => chunks.push(chunk)); doc.on('end', () => resolve(Buffer.concat(chunks))); doc.on('error', reject);
      const title = 'Firewall List Traffic Report';
      doc.fontSize(24).fillColor('#0f172a').text(title, { align: 'center' });
      doc.moveDown(0.4).fontSize(10).fillColor('#64748b').text(`Period: ${filters.startDate || 'All available data'} - ${filters.endDate || 'Now'}`, { align: 'center' });
      doc.moveDown(1.5);
      for (const list of ['Blacklist', 'Whitelist'] as const) {
        const items = rows.filter((row) => row.list === list);
        doc.fontSize(15).fillColor(list === 'Blacklist' ? '#b91c1c' : '#047857').text(`${list} (${items.length})`);
        doc.moveDown(0.5);
        if (!items.length) { doc.fontSize(10).fillColor('#64748b').text(`No ${list.toLowerCase()} entries.`); doc.moveDown(); continue; }
        this.tableHeader(doc); let y = doc.y;
        for (const row of items) {
          if (y > 740) { doc.addPage(); this.tableHeader(doc); y = doc.y; }
          doc.fillColor('#0f172a').fontSize(8.5).text(row.ip, 45, y, { width: 95 });
          doc.fillColor('#475569').text(row.reason, 142, y, { width: 125, ellipsis: true });
          doc.fillColor('#0f172a').text(row.events.toLocaleString(), 270, y, { width: 55, align: 'right' });
          doc.text(this.formatBytes(row.bytes), 332, y, { width: 75, align: 'right' });
          doc.fillColor('#475569').text(new Date(row.addedAt).toLocaleDateString(), 414, y, { width: 65 });
          y += 22;
        }
        doc.y = y + 8; doc.moveDown();
      }
      doc.fontSize(8).fillColor('#64748b').text('Traffic is calculated from byte fields present in Wazuh events. “No byte data” means the source event did not include byte counters.');
      doc.end();
    });
  }

  private tableHeader(doc: any) {
    const y = doc.y; doc.rect(42, y, 510, 19).fill('#e2e8f0'); doc.fontSize(8).fillColor('#334155');
    [['IP Address', 45], ['Reason', 142], ['Events', 270], ['Traffic', 332], ['Added', 414]].forEach(([text, x]) => doc.text(text as string, x as number, y + 6));
    doc.y = y + 25;
  }

  private async excel(rows: ListRow[], filters: any): Promise<Buffer> {
    const workbook = new Workbook(); const sheet = workbook.addWorksheet('Firewall List Traffic');
    sheet.columns = [{ width: 14 }, { width: 18 }, { width: 30 }, { width: 18 }, { width: 14 }, { width: 16 }, { width: 16 }];
    sheet.mergeCells('A1:G1'); sheet.getCell('A1').value = 'Firewall List Traffic Report'; sheet.getCell('A1').font = { bold: true, size: 18, color: { argb: 'FF0F172A' } };
    sheet.addRow([`Period: ${filters.startDate || 'All data'} - ${filters.endDate || 'Now'}`]); sheet.addRow([]);
    const header = sheet.addRow(['List', 'IP Address', 'Reason', 'Added By', 'Added Date', 'Observed Events', 'Traffic (bytes)']);
    header.font = { bold: true, color: { argb: 'FFFFFFFF' } }; header.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF334155' } };
    rows.forEach((row) => sheet.addRow([row.list, row.ip, row.reason, row.addedBy, row.addedAt, row.events, row.bytes]));
    const result = await workbook.xlsx.writeBuffer(); return Buffer.from(result);
  }
}
