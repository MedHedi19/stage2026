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
  private readonly httpsAgent: https.Agent;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.httpsAgent = new https.Agent({
      rejectUnauthorized: this.configService.get<string>('WAZUH_SSL_VERIFY') !== 'false',
    });
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
        this.httpService.post(`${url}/security/user/authenticate`, {}, {
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
      this.logger.error(`Wazuh Manager authentication failed: ${error.message}`, error.stack);
      throw error;
    }
  }

  async fetchAgents(): Promise<any[]> {
    const result = await this.requestWazuh('/agents?select=id,name,status,ip,version,os.name');
    if (result && result.data && result.data.affected_items) {
      return result.data.affected_items;
    }

    throw new Error('Wazuh agents payload is empty');
  }

  async fetchRecentAlerts(filters: {
    severity?: number;
    ip?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
  }): Promise<WazuhAlert[]> {
    try {
      const { url, user, password } = this.getApiConfig();
      const indexerUrl = url.replace(':55000', ':9200');

      const payload: any = {
        query: {
          bool: {
            must: [],
          },
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: filters.limit || 50,
      };

      if (filters.severity !== undefined) {
        payload.query.bool.must.push({
          range: { 'rule.level': { gte: filters.severity } },
        });
      }

      if (filters.ip) {
        payload.query.bool.must.push({
          multi_match: {
            query: filters.ip,
            fields: ['data.src_ip', 'data.dest_ip', 'agent.ip'],
          },
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
        }),
      );

      if (response.data && response.data.hits && response.data.hits.hits) {
        return response.data.hits.hits.map(hit => ({
          id: hit._id,
          timestamp: hit._source.timestamp,
          rule: hit._source.rule,
          agent: hit._source.agent,
          data: hit._source.data || {},
        }));
      }

      throw new Error('Wazuh alerts payload is empty');
    } catch (error) {
      this.logger.error(`Wazuh Indexer search failed: ${error.message}`, error.stack);
      throw error;
    }
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

  async requestWazuh(endpoint: string, method: 'GET' | 'POST' = 'GET', data?: any): Promise<any> {
    try {
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
    } catch (error) {
      this.logger.error(`Wazuh API request failed [${method} ${endpoint}]: ${error.message}`, error.stack);
      throw error;
    }
  }
}
