import { Injectable } from '@nestjs/common';
import { ReportGenerator, ReportGeneratorData, GeneratedReport } from '../interfaces/report-generator.interface';
import { ReportType } from '../report-types.enum';
import { AuditService } from '../../audit/audit.service';
import PDFDocument from 'pdfkit';
import { Workbook } from 'exceljs';

@Injectable()
export class UserActivityGenerator implements ReportGenerator {
  constructor(
    private readonly auditService: AuditService,
  ) {}

  getReportTypeName(): string {
    return 'User Activity';
  }

  async generate(data: ReportGeneratorData): Promise<GeneratedReport> {
    const { format, filters } = data;
    
    // Fetch user activity data from audit logs
    const auditLogs = await this.auditService.findAll({
      startDate: filters.startDate,
      endDate: filters.endDate,
    });

    const activityData = this.processUserActivity(auditLogs);
    const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');

    let buffer: Buffer;
    let filename: string;

    if (format === 'pdf') {
      buffer = await this.generatePdfBuffer(activityData, filters);
      filename = `user-activity-${timestampStr}.pdf`;
    } else {
      buffer = await this.generateExcelBuffer(activityData, filters);
      filename = `user-activity-${timestampStr}.xlsx`;
    }

    return { buffer, filename };
  }

  private processUserActivity(auditLogs: any[]) {
    // User activity summary
    const userActivity: Record<string, { 
      loginCount: number; 
      logoutCount: number; 
      actions: number; 
      lastSeen: string; 
      firstSeen: string;
      actionTypes: Record<string, number>;
      ipAddresses: Set<string>;
    }> = {};

    // Action type distribution
    const actionDistribution: Record<string, number> = {};

    // Timeline analysis
    const activityByHour: Record<string, number> = {};
    const activityByDay: Record<string, number> = {};

    // Geographic distribution (by IP)
    const ipActivity: Record<string, { count: number; users: Set<string> }> = {};

    // Security events
    const securityEvents: Record<string, number> = {
      'Failed Login Attempts': 0,
      'Permission Changes': 0,
      'Configuration Changes': 0,
      'Data Access': 0,
      'Export Activities': 0,
    };

    auditLogs.forEach(log => {
      const username = log.username || 'Unknown';
      const action = log.action || 'Unknown';
      const timestamp = log.timestamp || new Date().toISOString();
      const ipAddress = log.ipAddress || 'Unknown';

      // Initialize user activity
      if (!userActivity[username]) {
        userActivity[username] = {
          loginCount: 0,
          logoutCount: 0,
          actions: 0,
          lastSeen: timestamp,
          firstSeen: timestamp,
          actionTypes: {},
          ipAddresses: new Set(),
        };
      }

      // Update user activity
      userActivity[username].actions++;
      userActivity[username].actionTypes[action] = (userActivity[username].actionTypes[action] || 0) + 1;
      userActivity[username].ipAddresses.add(ipAddress);

      if (new Date(timestamp) > new Date(userActivity[username].lastSeen)) {
        userActivity[username].lastSeen = timestamp;
      }
      if (new Date(timestamp) < new Date(userActivity[username].firstSeen)) {
        userActivity[username].firstSeen = timestamp;
      }

      // Track login/logout
      if (action.toLowerCase().includes('login') || action.toLowerCase().includes('authenticate')) {
        userActivity[username].loginCount++;
      }
      if (action.toLowerCase().includes('logout') || action.toLowerCase().includes('sign out')) {
        userActivity[username].logoutCount++;
      }

      // Action distribution
      actionDistribution[action] = (actionDistribution[action] || 0) + 1;

      // Timeline analysis
      const date = new Date(timestamp);
      const hour = date.getHours();
      const day = date.toLocaleDateString('en-US', { weekday: 'long' });
      
      activityByHour[`${hour}:00`] = (activityByHour[`${hour}:00`] || 0) + 1;
      activityByDay[day] = (activityByDay[day] || 0) + 1;

      // IP activity
      if (!ipActivity[ipAddress]) {
        ipActivity[ipAddress] = { count: 0, users: new Set() };
      }
      ipActivity[ipAddress].count++;
      ipActivity[ipAddress].users.add(username);

      // Security events
      if (action.toLowerCase().includes('failed') || action.toLowerCase().includes('authentication failed')) {
        securityEvents['Failed Login Attempts']++;
      }
      if (action.toLowerCase().includes('permission') || action.toLowerCase().includes('role')) {
        securityEvents['Permission Changes']++;
      }
      if (action.toLowerCase().includes('config') || action.toLowerCase().includes('setting')) {
        securityEvents['Configuration Changes']++;
      }
      if (action.toLowerCase().includes('data') || action.toLowerCase().includes('access')) {
        securityEvents['Data Access']++;
      }
      if (action.toLowerCase().includes('export') || action.toLowerCase().includes('download')) {
        securityEvents['Export Activities']++;
      }
    });

    // Convert Sets to Arrays and process data
    const processedUserActivity = Object.entries(userActivity).map(([username, data]) => ({
      username,
      ...data,
      ipAddresses: Array.from(data.ipAddresses),
      totalSessions: data.loginCount,
      uniqueActions: Object.keys(data.actionTypes).length,
      mostCommonAction: Object.entries(data.actionTypes).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A',
    }));

    // Sort users by activity level
    const topUsers = processedUserActivity
      .sort((a, b) => b.actions - a.actions)
      .slice(0, 15);

    // Calculate activity patterns
    const peakActivityHour = Object.entries(activityByHour)
      .sort((a, b) => (b[1] as number) - (a[1] as number))[0]?.[0] || 'N/A';

    const peakActivityDay = Object.entries(activityByDay)
      .sort((a, b) => (b[1] as number) - (a[1] as number))[0]?.[0] || 'N/A';

    // Anomalous activity detection
    const anomalousUsers = processedUserActivity.filter(user => {
      const avgActions = processedUserActivity.reduce((sum, u) => sum + u.actions, 0) / processedUserActivity.length;
      return user.actions > avgActions * 3; // More than 3x average
    });

    // Recent activity (last 24 hours)
    const recentActivity = auditLogs.filter(log => {
      const logDate = new Date(log.timestamp);
      const dayAgo = new Date();
      dayAgo.setDate(dayAgo.getDate() - 1);
      return logDate > dayAgo;
    });

    return {
      summary: {
        period: auditLogs.length > 0 ? `${new Date(auditLogs[auditLogs.length - 1]?.timestamp).toLocaleDateString()} - ${new Date(auditLogs[0]?.timestamp).toLocaleDateString()}` : 'N/A',
        totalUsers: Object.keys(userActivity).length,
        totalActions: auditLogs.length,
        totalLogins: Object.values(userActivity).reduce((sum, u) => sum + u.loginCount, 0),
        uniqueIPs: Object.keys(ipActivity).length,
        securityEvents: Object.values(securityEvents).reduce((sum, count) => sum + count, 0),
      },
      userActivity: processedUserActivity,
      topUsers,
      actionDistribution,
      activityByHour: Object.entries(activityByHour).map(([hour, count]) => ({ hour, count })),
      activityByDay: Object.entries(activityByDay).map(([day, count]) => ({ day, count })),
      ipActivity: Object.entries(ipActivity).map(([ip, data]) => ({
        ip,
        count: data.count,
        users: Array.from(data.users),
        uniqueUsers: data.users.size,
      })).sort((a, b) => b.count - a.count),
      securityEvents,
      peakActivityHour,
      peakActivityDay,
      anomalousUsers,
      recentActivityCount: recentActivity.length,
      complianceMetrics: this.calculateComplianceMetrics(auditLogs),
    };
  }

  private calculateComplianceMetrics(auditLogs: any[]) {
    const totalLogs = auditLogs.length;
    const logsWithIP = auditLogs.filter(log => log.ipAddress).length;
    const logsWithTimestamp = auditLogs.filter(log => log.timestamp).length;
    const uniqueUsers = new Set(auditLogs.map(log => log.username)).size;

    return {
      auditTrailCompleteness: totalLogs > 0 ? `${((logsWithTimestamp / totalLogs) * 100).toFixed(1)}%` : 'N/A',
      ipLoggingRate: totalLogs > 0 ? `${((logsWithIP / totalLogs) * 100).toFixed(1)}%` : 'N/A',
      userCoverage: uniqueUsers > 0 ? '100%' : 'N/A',
      averageLogsPerUser: uniqueUsers > 0 ? (totalLogs / uniqueUsers).toFixed(1) : 'N/A',
    };
  }

  private async generatePdfBuffer(data: any, filters: any): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 40, size: 'A4' });
        const chunks: Buffer[] = [];

        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', err => reject(err));

        // User Activity Header
        doc.fontSize(22).fillColor('#0b192c').text('User Activity Report', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).fillColor('gray').text(`Report Period: ${data.summary.period}`, { align: 'center' });
        doc.fontSize(10).fillColor('gray').text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.moveDown(2);

        // Activity Summary
        doc.fontSize(16).fillColor('#0b192c').text('Activity Summary', { underline: true });
        doc.moveDown();

        const summaryMetrics = [
          ['Total Users', data.summary.totalUsers.toString()],
          ['Total Actions', data.summary.totalActions.toLocaleString()],
          ['Total Logins', data.summary.totalLogins.toLocaleString()],
          ['Unique IPs', data.summary.uniqueIPs.toString()],
          ['Security Events', data.summary.securityEvents.toString()],
        ];

        let yPos = doc.y;
        summaryMetrics.forEach(([label, value]) => {
          doc.fontSize(11).fillColor('#64748b').text(label, 50, yPos);
          doc.fillColor('#0b192c').text(value, 200, yPos);
          yPos += 20;
        });

        doc.y = yPos + 10;
        doc.moveDown();

        // Compliance Metrics
        doc.fontSize(16).fillColor('#0b192c').text('Compliance Metrics', { underline: true });
        doc.moveDown();

        Object.entries(data.complianceMetrics).forEach(([metric, value]) => {
          doc.fontSize(11).fillColor('#64748b').text(`${metric}:`, 50, doc.y);
          doc.fillColor('#0b192c').text(value, 200, doc.y);
          doc.moveDown(0.5);
        });

        doc.addPage();

        // Top Users
        doc.fontSize(16).fillColor('#0b192c').text('Most Active Users', { underline: true });
        doc.moveDown();

        const tableTop = doc.y;
        doc.fontSize(10).fillColor('#64748b');
        doc.text('User', 50, tableTop);
        doc.text('Actions', 150, tableTop);
        doc.text('Logins', 220, tableTop);
        doc.text('Unique IPs', 290, tableTop);
        doc.text('Activity Level', 380, tableTop);

        doc.moveDown(0.5);
        let rowY = doc.y;

        data.topUsers.forEach((user, index) => {
          const activityLevel = user.actions > 100 ? 'Very High' : user.actions > 50 ? 'High' : user.actions > 20 ? 'Medium' : 'Low';
          const activityColor = activityLevel === 'Very High' ? '#ef4444' : activityLevel === 'High' ? '#f59e0b' : activityLevel === 'Medium' ? '#3b82f6' : '#10b981';

          doc.fontSize(9).fillColor('black').text(user.username, 50, rowY);
          doc.text(user.actions.toString(), 150, rowY);
          doc.text(user.totalSessions.toString(), 220, rowY);
          doc.text(user.ipAddresses.length.toString(), 290, rowY);
          doc.fillColor(activityColor).text(activityLevel, 380, rowY);
          rowY += 20;
        });

        doc.addPage();

        // Security Events
        doc.fontSize(16).fillColor('#0b192c').text('Security Events', { underline: true });
        doc.moveDown();

        Object.entries(data.securityEvents).forEach(([event, count]) => {
          if (count > 0) {
            doc.fontSize(11).fillColor('#0b192c').text(event);
            doc.fontSize(10).fillColor('#64748b').text(`Count: ${count}`);
            doc.moveDown(0.5);
          }
        });

        if (data.anomalousUsers.length > 0) {
          doc.moveDown();
          doc.fontSize(16).fillColor('#ef4444').text('Anomalous Activity Detected', { underline: true });
          doc.moveDown();

          data.anomalousUsers.forEach(user => {
            doc.fontSize(10).fillColor('black').text(`${user.username}: ${user.actions} actions (avg: ${(data.summary.totalActions / data.summary.totalUsers).toFixed(0)})`);
            doc.moveDown(0.3);
          });
        }

        doc.addPage();

        // Activity Patterns
        doc.fontSize(16).fillColor('#0b192c').text('Activity Patterns', { underline: true });
        doc.moveDown();

        doc.fontSize(12).fillColor('#0b192c').text(`Peak Activity Hour: ${data.peakActivityHour}`);
        doc.fontSize(12).fillColor('#0b192c').text(`Peak Activity Day: ${data.peakActivityDay}`);
        doc.moveDown();

        doc.fontSize(14).fillColor('#0b192c').text('Activity by Hour');
        doc.moveDown();

        data.activityByHour.forEach(({ hour, count }) => {
          doc.fontSize(10).text(`${hour}: ${count} actions`);
          doc.moveDown(0.2);
        });

        doc.moveDown();
        doc.fontSize(14).fillColor('#0b192c').text('Activity by Day');
        doc.moveDown();

        data.activityByDay.forEach(({ day, count }) => {
          doc.fontSize(10).text(`${day}: ${count} actions`);
          doc.moveDown(0.2);
        });

        doc.addPage();

        // IP Address Analysis
        doc.fontSize(16).fillColor('#0b192c').text('IP Address Analysis', { underline: true });
        doc.moveDown();

        const ipTableTop = doc.y;
        doc.fontSize(10).fillColor('#64748b');
        doc.text('IP Address', 50, ipTableTop);
        doc.text('Activity Count', 200, ipTableTop);
        doc.text('Unique Users', 320, ipTableTop);
        doc.text('Risk Level', 450, ipTableTop);

        doc.moveDown(0.5);
        let ipRowY = doc.y;

        data.ipActivity.slice(0, 15).forEach(({ ip, count, uniqueUsers }) => {
          const riskLevel = count > 50 ? 'High' : count > 20 ? 'Medium' : 'Low';
          const riskColor = riskLevel === 'High' ? '#ef4444' : riskLevel === 'Medium' ? '#f59e0b' : '#10b981';

          doc.fontSize(9).fillColor('black').text(ip, 50, ipRowY);
          doc.text(count.toString(), 200, ipRowY);
          doc.text(uniqueUsers.toString(), 320, ipRowY);
          doc.fillColor(riskColor).text(riskLevel, 450, ipRowY);
          ipRowY += 20;
        });

        // Action Distribution
        doc.addPage();
        doc.fontSize(16).fillColor('#0b192c').text('Action Type Distribution', { underline: true });
        doc.moveDown();

        const topActions = Object.entries(data.actionDistribution)
          .sort((a, b) => (b[1] as number) - (a[1] as number))
          .slice(0, 15);

        topActions.forEach(([action, count]) => {
          const percentage = data.summary.totalActions > 0 
            ? ((count / data.summary.totalActions) * 100).toFixed(1)
            : '0.0';
          
          doc.fontSize(10).fillColor('black').text(`${action}: ${count} (${percentage}%)`);
          doc.moveDown(0.3);
        });

        // Recent Activity
        doc.addPage();
        doc.fontSize(16).fillColor('#0b192c').text('Recent Activity (Last 24 Hours)', { underline: true });
        doc.moveDown();

        doc.fontSize(11).fillColor('#64748b').text(`Total Recent Actions: ${data.recentActivityCount}`);
        doc.moveDown();

        doc.fontSize(14).fillColor('#0b192c').text('Audit Trail Recommendations');
        doc.moveDown();

        const recommendations = this.generateRecommendations(data);
        recommendations.forEach((rec, index) => {
          doc.fontSize(10).fillColor('black').text(`${index + 1}. ${rec}`);
          doc.moveDown(0.5);
        });

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  private generateRecommendations(data: any): string[] {
    const recommendations = [];

    if (data.anomalousUsers.length > 0) {
      recommendations.push(`Investigate ${data.anomalousUsers.length} user(s) with anomalous activity patterns exceeding normal thresholds.`);
    }

    if (data.securityEvents['Failed Login Attempts'] > 10) {
      recommendations.push(`Review ${data.securityEvents['Failed Login Attempts']} failed login attempts - potential brute force attack detected.`);
    }

    if (data.complianceMetrics.ipLoggingRate !== '100%') {
      recommendations.push(`Improve IP logging coverage. Current rate: ${data.complianceMetrics.ipLoggingRate}`);
    }

    if (data.ipActivity.some(ip => ip.uniqueUsers > 5)) {
      recommendations.push('Review shared IP addresses with multiple user accounts for potential security risks.');
    }

    recommendations.push('Continue regular audit log review and analysis.');
    recommendations.push('Consider implementing automated alerting for suspicious user activity patterns.');
    recommendations.push('Review and update user access privileges quarterly.');

    return recommendations;
  }

  private async generateExcelBuffer(data: any, filters: any): Promise<Buffer> {
    const workbook = new Workbook();
    const worksheet = workbook.addWorksheet('User Activity');

    // Styling
    const headerStyle = {
      font: { bold: true, size: 12, color: { argb: 'FFFFFFFF' } },
      fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0B192C' } },
      alignment: { horizontal: 'center' }
    };

    const titleStyle = {
      font: { bold: true, size: 16, color: { argb: 'FF0B192C' } },
      alignment: { horizontal: 'center' }
    };

    // Title
    worksheet.mergeCells('A1:F1');
    worksheet.getCell('A1').value = 'User Activity Report';
    worksheet.getCell('A1').style = titleStyle;

    worksheet.mergeCells('A2:F2');
    worksheet.getCell('A2').value = `Report Period: ${data.summary.period}`;
    worksheet.getCell('A2').style = { font: { size: 10 }, alignment: { horizontal: 'center' } };

    // Summary
    let row = 4;
    worksheet.getCell(`A${row}`).value = 'Activity Summary';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:F${row}`);
    row++;

    const summaryData = [
      ['Metric', 'Value', 'Status', 'Trend'],
      ['Total Users', data.summary.totalUsers.toString(), 'Active', '→'],
      ['Total Actions', data.summary.totalActions.toLocaleString(), 'All', '↑'],
      ['Total Logins', data.summary.totalLogins.toLocaleString(), 'Sessions', '→'],
      ['Unique IPs', data.summary.uniqueIPs.toString(), 'Network', '→'],
      ['Security Events', data.summary.securityEvents.toString(), 'Monitored', '↓'],
    ];

    summaryData.forEach((metric, index) => {
      metric.forEach((value, col) => {
        const cell = worksheet.getCell(row, col + 1);
        cell.value = value;
        if (index === 0) {
          cell.style = headerStyle;
        }
      });
      row++;
    });

    // Compliance Metrics
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Compliance Metrics';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:F${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Metric';
    worksheet.getCell(`B${row}`).value = 'Value';
    worksheet.getCell(`C${row}`).value = 'Status';
    row++;

    Object.entries(data.complianceMetrics).forEach(([metric, value]) => {
      const status = value === '100%' || value === 'N/A' ? 'Compliant' : parseFloat(value) > 90 ? 'Good' : 'Needs Improvement';
      
      worksheet.getCell(`A${row}`).value = metric;
      worksheet.getCell(`B${row}`).value = value;
      worksheet.getCell(`C${row}`).value = status;
      row++;
    });

    // Top Users
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Most Active Users';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:F${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Username';
    worksheet.getCell(`B${row}`).value = 'Total Actions';
    worksheet.getCell(`C${row}`).value = 'Logins';
    worksheet.getCell(`D${row}`).value = 'Unique IPs';
    worksheet.getCell(`E${row}`).value = 'Activity Level';
    worksheet.getCell(`F${row}`).value = 'Most Common Action';
    row++;

    data.topUsers.forEach(user => {
      const activityLevel = user.actions > 100 ? 'Very High' : user.actions > 50 ? 'High' : user.actions > 20 ? 'Medium' : 'Low';
      
      worksheet.getCell(`A${row}`).value = user.username;
      worksheet.getCell(`B${row}`).value = user.actions;
      worksheet.getCell(`C${row}`).value = user.totalSessions;
      worksheet.getCell(`D${row}`).value = user.ipAddresses.length;
      worksheet.getCell(`E${row}`).value = activityLevel;
      worksheet.getCell(`F${row}`).value = user.mostCommonAction;
      row++;
    });

    // Security Events
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Security Events';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:C${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Event Type';
    worksheet.getCell(`B${row}`).value = 'Count';
    worksheet.getCell(`C${row}`).value = 'Risk Level';
    row++;

    Object.entries(data.securityEvents).forEach(([event, count]) => {
      const riskLevel = count > 10 ? 'High' : count > 5 ? 'Medium' : count > 0 ? 'Low' : 'None';
      
      worksheet.getCell(`A${row}`).value = event;
      worksheet.getCell(`B${row}`).value = count;
      worksheet.getCell(`C${row}`).value = riskLevel;
      row++;
    });

    // Activity Patterns
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Activity Patterns';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:C${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Pattern';
    worksheet.getCell(`B${row}`).value = 'Value';
    worksheet.getCell(`C${row}`).value = 'Insight';
    row++;

    worksheet.getCell(`A${row}`).value = 'Peak Activity Hour';
    worksheet.getCell(`B${row}`).value = data.peakActivityHour;
    worksheet.getCell(`C${row}`).value = 'Resource Planning';
    row++;

    worksheet.getCell(`A${row}`).value = 'Peak Activity Day';
    worksheet.getCell(`B${row}`).value = data.peakActivityDay;
    worksheet.getCell(`C${row}`).value = 'Scheduling';
    row++;

    // IP Address Analysis
    row += 2;
    worksheet.getCell(`A${row}`).value = 'IP Address Analysis';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:E${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'IP Address';
    worksheet.getCell(`B${row}`).value = 'Activity Count';
    worksheet.getCell(`C${row}`).value = 'Unique Users';
    worksheet.getCell(`D${row}`).value = 'Risk Level';
    worksheet.getCell(`E${row}`).value = 'Action';
    row++;

    data.ipActivity.slice(0, 20).forEach(({ ip, count, uniqueUsers }) => {
      const riskLevel = count > 50 ? 'High' : count > 20 ? 'Medium' : 'Low';
      const action = riskLevel === 'High' ? 'Investigate' : riskLevel === 'Medium' ? 'Monitor' : 'Normal';
      
      worksheet.getCell(`A${row}`).value = ip;
      worksheet.getCell(`B${row}`).value = count;
      worksheet.getCell(`C${row}`).value = uniqueUsers;
      worksheet.getCell(`D${row}`).value = riskLevel;
      worksheet.getCell(`E${row}`).value = action;
      row++;
    });

    // Action Distribution
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Action Type Distribution';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:C${row}`);
    row++;

    worksheet.getCell(`A${row}`).value = 'Action Type';
    worksheet.getCell(`B${row}`).value = 'Count';
    worksheet.getCell(`C${row}`).value = 'Percentage';
    row++;

    const topActions = Object.entries(data.actionDistribution)
      .sort((a, b) => (b[1] as number) - (a[1] as number))
      .slice(0, 15);

    topActions.forEach(([action, count]) => {
      const percentage = data.summary.totalActions > 0 
        ? ((count / data.summary.totalActions) * 100).toFixed(1)
        : '0.0';
      
      worksheet.getCell(`A${row}`).value = action;
      worksheet.getCell(`B${row}`).value = count;
      worksheet.getCell(`C${row}`).value = `${percentage}%`;
      row++;
    });

    // Anomalous Users
    if (data.anomalousUsers.length > 0) {
      row += 2;
      worksheet.getCell(`A${row}`).value = 'Anomalous Activity Detection';
      worksheet.getCell(`A${row}`).style = headerStyle;
      worksheet.mergeCells(`A${row}:D${row}`);
      row++;

      worksheet.getCell(`A${row}`).value = 'Username';
      worksheet.getCell(`B${row}`).value = 'Action Count';
      worksheet.getCell(`C${row}`).value = 'vs Average';
      worksheet.getCell(`D${row}`).value = 'Recommendation';
      row++;

      const avgActions = (data.summary.totalActions / data.summary.totalUsers).toFixed(0);

      data.anomalousUsers.forEach(user => {
        worksheet.getCell(`A${row}`).value = user.username;
        worksheet.getCell(`B${row}`).value = user.actions;
        worksheet.getCell(`C${row}`).value = avgActions;
        worksheet.getCell(`D${row}`).value = 'Investigate';
        row++;
      });
    }

    // Recommendations
    row += 2;
    worksheet.getCell(`A${row}`).value = 'Audit Trail Recommendations';
    worksheet.getCell(`A${row}`).style = headerStyle;
    worksheet.mergeCells(`A${row}:F${row}`);
    row++;

    const recommendations = this.generateRecommendations(data);
    recommendations.forEach((rec, index) => {
      worksheet.getCell(`A${row}`).value = `${index + 1}. ${rec}`;
      worksheet.mergeCells(`A${row}:F${row}`);
      row++;
    });

    // Column widths
    worksheet.columns = [
      { width: 25 },
      { width: 20 },
      { width: 15 },
      { width: 20 },
      { width: 20 },
      { width: 30 },
    ];

    const buffer = await workbook.xlsx.writeBuffer();
    return Buffer.from(buffer);
  }
}