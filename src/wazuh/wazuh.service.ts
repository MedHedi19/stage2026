import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { lastValueFrom } from 'rxjs';
import * as https from 'https';

export interface WazuhAlert {
  id: string;
  timestamp: string;
  rule: {
    id: string;
    level: number;
    description: string;
    groups: string[];
  };
  agent: {
    id: string;
    name: string;
    ip?: string;
  };
  data: {
    src_ip?: string;
    dest_ip?: string;
    src_port?: number;
    dest_port?: number;
    protocol?: string;
    path?: string;
    modification?: string;
  };
}

@Injectable()
export class WazuhService {
  private readonly logger = new Logger(WazuhService.name);
  private wazuhToken: string | null = null;
  private tokenExpiry: number | null = null;

  private readonly httpsAgent = new https.Agent({
    rejectUnauthorized: false,
  });

  // Simulated static data for fallback / local development
  private simulatedAgents = [
    { id: '000', name: 'wazuh-manager', status: 'active', ip: '127.0.0.1', os: { name: 'Ubuntu' }, version: 'v4.7.2' },
    { id: '001', name: 'suricata-sensor', status: 'active', ip: '192.168.101.128', os: { name: 'Debian' }, version: 'v4.7.2' },
    { id: '002', name: 'windows-db-prod', status: 'active', ip: '192.168.101.144', os: { name: 'Windows Server' }, version: 'v4.7.2' },
    { id: '003', name: 'analyst-workstation', status: 'disconnected', ip: '192.168.101.155', os: { name: 'Windows 11' }, version: 'v4.7.2' },
    { id: '004', name: 'apache-web-server', status: 'active', ip: '192.168.101.130', os: { name: 'Ubuntu' }, version: 'v4.7.2' },
  ];

  private simulatedAlerts: WazuhAlert[] = [];

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.generateSimulatedAlerts();
  }

  private generateSimulatedAlerts() {
    const types = [
      { id: '100001', level: 12, description: 'Suricata: SQL Injection Attempt detected', groups: ['ids', 'suricata', 'web_attack'], category: 'SQL Injection' },
      { id: '5716', level: 9, description: 'Wazuh: Multiple SSH authentication failures', groups: ['syslog', 'sshd', 'authentication_failed'], category: 'Brute Force' },
      { id: '100002', level: 15, description: 'Suricata: Shellshock exploit attempt', groups: ['ids', 'suricata', 'exploit'], category: 'Exploit' },
      { id: '5501', level: 7, description: 'Wazuh: User added to sudoers group', groups: ['syslog', 'audit', 'privilege_escalation'], category: 'Privilege Escalation' },
      { id: '100003', level: 10, description: 'Suricata: Nmap port scan detected', groups: ['ids', 'suricata', 'reconnaissance'], category: 'Port Scan' },
      { id: '5502', level: 5, description: 'Wazuh: File Integrity Monitoring - File modified in /etc', groups: ['fim', 'syscheck'], category: 'FIM' }
    ];

    const agents = this.simulatedAgents.filter(a => a.id !== '003'); // active ones
    const srcIps = ['195.14.28.32', '45.132.8.99', '82.165.10.11', '192.168.101.155'];

    // Generate 50 realistic historical alerts spanning the last 24 hours
    for (let i = 0; i < 50; i++) {
      const type = types[Math.floor(Math.random() * types.length)];
      const agent = agents[Math.random() === 0 ? 0 : Math.floor(Math.random() * agents.length)];
      const src_ip = srcIps[Math.floor(Math.random() * srcIps.length)];
      const minutesAgo = i * 28 + Math.floor(Math.random() * 15);
      
      this.simulatedAlerts.push({
        id: `alert-sim-${10000 + i}`,
        timestamp: new Date(Date.now() - minutesAgo * 60 * 1000).toISOString(),
        rule: {
          id: type.id,
          level: type.level,
          description: type.description,
          groups: type.groups,
        },
        agent: {
          id: agent.id,
          name: agent.name,
          ip: agent.ip,
        },
        data: {
          src_ip,
          dest_ip: agent.ip,
          src_port: Math.floor(Math.random() * 16383) + 49152,
          dest_port: type.id === '5716' ? 22 : 80,
          protocol: 'TCP',
          path: type.id === '5502' ? '/etc/resolv.conf' : undefined,
          modification: type.id === '5502' ? 'size and sha1 changed' : undefined,
        }
      });
    }
  }

  private getApiConfig() {
    const url = this.configService.get<string>('WAZUH_API_URL') || 'https://192.168.101.128:55000';
    const user = this.configService.get<string>('WAZUH_API_USER') || 'wazuh-wui';
    const password = this.configService.get<string>('WAZUH_API_PASSWORD') || '';
    return { url, user, password };
  }

  async getWazuhToken(): Promise<string> {
    const now = Date.now();
    const cachedToken = this.wazuhToken;
    if (cachedToken && this.tokenExpiry && now < this.tokenExpiry) {
      return cachedToken;
    }

    const { url, user, password } = this.getApiConfig();
    try {
      const authHeader = Buffer.from(`${user}:${password}`).toString('base64');
      const response = await lastValueFrom(
        this.httpService.get(`${url}/security/user/authenticate`, {
          headers: {
            Authorization: `Basic ${authHeader}`,
          },
          httpsAgent: this.httpsAgent,
          timeout: 4000,
        }),
      );

      if (response.data && response.data.data && response.data.data.token) {
        const token = response.data.data.token;
        this.wazuhToken = token;
        this.tokenExpiry = Date.now() + 50 * 60 * 1000;
        return token;
      }
      throw new Error('Token missing in authentication payload');
    } catch (error) {
      this.logger.warn(`Wazuh Manager authentication failed: ${error.message}. Operating in Simulated/Offline mode.`);
      throw error;
    }
  }

  async fetchAgents(): Promise<any[]> {
    try {
      const result = await this.requestWazuh('/agents?select=id,name,status,ip,version,os.name');
      if (result && result.data && result.data.affected_items) {
        return result.data.affected_items;
      }
      return this.simulatedAgents;
    } catch (e) {
      this.logger.debug('Returning simulated agents status list');
      return this.simulatedAgents;
    }
  }

  async fetchRecentAlerts(filters: {
    severity?: number;
    ip?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
  }): Promise<WazuhAlert[]> {
    // Attempt real Wazuh Indexer integration if possible
    // Note: Wazuh Indexer normally runs on port 9200
    try {
      const { url, user, password } = this.getApiConfig();
      // Derive Indexer URL from Manager API URL by replacing port 55000 with 9200
      const indexerUrl = url.replace(':55000', ':9200');
      
      const payload: any = {
        query: {
          bool: {
            must: []
          }
        },
        sort: [
          { timestamp: { order: 'desc' } }
        ],
        size: filters.limit || 50
      };

      if (filters.severity) {
        payload.query.bool.must.push({
          range: { 'rule.level': { gte: filters.severity } }
        });
      }

      if (filters.ip) {
        payload.query.bool.must.push({
          multi_match: {
            query: filters.ip,
            fields: ['data.src_ip', 'data.dest_ip', 'agent.ip']
          }
        });
      }

      if (filters.startDate || filters.endDate) {
        const range: any = {};
        if (filters.startDate) range.gte = filters.startDate;
        if (filters.endDate) range.lte = filters.endDate;
        payload.query.bool.must.push({ range: { timestamp: range } });
      }

      if (payload.query.bool.must.length === 0) {
        payload.query.bool.must.push({ match_all: {} });
      }

      const response = await lastValueFrom(
        this.httpService.post(`${indexerUrl}/wazuh-alerts-*/_search`, payload, {
          headers: {
            Authorization: `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`,
          },
          httpsAgent: this.httpsAgent,
          timeout: 3000,
        })
      );

      if (response.data && response.data.hits && response.data.hits.hits) {
        return response.data.hits.hits.map(hit => ({
          id: hit._id,
          timestamp: hit._source.timestamp,
          rule: hit._source.rule,
          agent: hit._source.agent,
          data: hit._source.data || {}
        }));
      }
    } catch (e) {
      this.logger.debug('Indexer query failed or offline. Returning simulated alerts.');
    }

    // SIMULATION FILTER LOGIC
    let alerts = [...this.simulatedAlerts];

    const severity = filters.severity;
    if (severity !== undefined) {
      alerts = alerts.filter(a => a.rule.level >= severity);
    }

    if (filters.ip) {
      const ipFilter = filters.ip.toLowerCase();
      alerts = alerts.filter(a => 
        a.data.src_ip?.includes(ipFilter) ||
        a.data.dest_ip?.includes(ipFilter) ||
        a.agent.ip?.includes(ipFilter)
      );
    }

    if (filters.startDate) {
      const start = new Date(filters.startDate).getTime();
      alerts = alerts.filter(a => new Date(a.timestamp).getTime() >= start);
    }

    if (filters.endDate) {
      const end = new Date(filters.endDate).getTime();
      alerts = alerts.filter(a => new Date(a.timestamp).getTime() <= end);
    }

    const limit = filters.limit || 50;
    return alerts.slice(0, limit);
  }

  async getAlertStats(filters: { startDate?: string; endDate?: string }): Promise<any> {
    const alerts = await this.fetchRecentAlerts({ ...filters, limit: 1000 });

    const totalAlerts = alerts.length;
    const severityDistribution: Record<string, number> = {};
    const attacksByType: Record<string, number> = {};
    const topSourceIps: Record<string, number> = {};
    const alertOverTime: Record<string, number> = {};

    alerts.forEach(alert => {
      // Severity distribution
      const level = alert.rule.level;
      severityDistribution[level] = (severityDistribution[level] || 0) + 1;

      // Grouping by type (Suricata description vs syslog description)
      const desc = alert.rule.description;
      let category = 'Other Security Event';
      if (desc.includes('SQL Injection')) category = 'SQL Injection';
      else if (desc.includes('SSH')) category = 'SSH Brute Force';
      else if (desc.includes('Shellshock')) category = 'Exploit (Shellshock)';
      else if (desc.includes('sudoers')) category = 'Privilege Escalation';
      else if (desc.includes('port scan') || desc.includes('Nmap')) category = 'Port Scanning';
      else if (desc.includes('File Integrity') || desc.includes('fim')) category = 'FIM Change';

      attacksByType[category] = (attacksByType[category] || 0) + 1;

      // Top source IPs
      const src = alert.data.src_ip || 'N/A';
      if (src !== 'N/A') {
        topSourceIps[src] = (topSourceIps[src] || 0) + 1;
      }

      // Over time (grouped by hour)
      const dateStr = alert.timestamp.substring(0, 13) + ':00:00Z'; // YYYY-MM-DDTHH
      alertOverTime[dateStr] = (alertOverTime[dateStr] || 0) + 1;
    });

    // Formatting top source IPs to sorted array
    const topSourceIpsList = Object.entries(topSourceIps)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Formatting alert volume over time to sorted array
    const overTimeList = Object.entries(alertOverTime)
      .map(([time, count]) => ({ time, count }))
      .sort((a, b) => a.time.localeCompare(b.time));

    return {
      totalAlerts,
      severityDistribution,
      attacksByType,
      topSourceIps: topSourceIpsList,
      alertsOverTime: overTimeList,
    };
  }

  // Hook to simulate new real-time alerts
  generateNewAlert(): WazuhAlert {
    const alertTypes = [
      { id: '100001', level: 12, description: 'Suricata: SQL Injection Attempt detected', groups: ['ids', 'suricata', 'web_attack'] },
      { id: '5716', level: 9, description: 'Wazuh: Multiple SSH authentication failures', groups: ['syslog', 'sshd', 'authentication_failed'] },
      { id: '100003', level: 11, description: 'Suricata: ET SCAN Suspicious inbound traffic', groups: ['ids', 'suricata', 'scan'] }
    ];
    const type = alertTypes[Math.floor(Math.random() * alertTypes.length)];
    const agent = this.simulatedAgents[1 + Math.floor(Math.random() * 3)]; // Debian, Win, or Ubuntu
    const srcIps = ['195.14.28.12', '45.132.8.22', '82.165.10.33'];

    const newAlert: WazuhAlert = {
      id: `alert-sim-rt-${Date.now()}`,
      timestamp: new Date().toISOString(),
      rule: {
        id: type.id,
        level: type.level,
        description: type.description,
        groups: type.groups,
      },
      agent: {
        id: agent.id,
        name: agent.name,
        ip: agent.ip,
      },
      data: {
        src_ip: srcIps[Math.floor(Math.random() * srcIps.length)],
        dest_ip: agent.ip,
        src_port: Math.floor(Math.random() * 16383) + 49152,
        dest_port: type.id === '5716' ? 22 : 80,
        protocol: 'TCP'
      }
    };

    // Prepend to simulated alerts to keep it fresh
    this.simulatedAlerts.unshift(newAlert);
    return newAlert;
  }

  async requestWazuh(endpoint: string, method: 'GET' | 'POST' = 'GET', data?: any): Promise<any> {
    const { url } = this.getApiConfig();
    const token = await this.getWazuhToken();

    const options = {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      httpsAgent: this.httpsAgent,
      timeout: 3000,
    };

    const response = method === 'POST'
      ? await lastValueFrom(this.httpService.post(`${url}${endpoint}`, data, options))
      : await lastValueFrom(this.httpService.get(`${url}${endpoint}`, options));

    return response.data;
  }
}
