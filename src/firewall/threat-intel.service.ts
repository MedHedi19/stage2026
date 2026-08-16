import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { lastValueFrom } from 'rxjs';

export interface ThreatIntelResult {
  abuseScore: number;
  totalReports: number;
  categories: number[];
  countryCode: string;
}

@Injectable()
export class ThreatIntelService {
  private readonly logger = new Logger(ThreatIntelService.name);
  private readonly apiKey: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.apiKey = this.configService.get<string>('ABUSEIPDB_API_KEY') || '';
    if (!this.apiKey) {
      this.logger.warn('ABUSEIPDB_API_KEY is not configured. Threat intelligence features will be disabled.');
    }
  }

  async checkIp(ip: string): Promise<ThreatIntelResult | null> {
    if (!this.apiKey) {
      this.logger.warn('AbuseIPDB API key not configured, skipping IP check');
      return null;
    }

    try {
      const response = await lastValueFrom(
        this.httpService.get('https://api.abuseipdb.com/api/v2/check', {
          headers: {
            Key: this.apiKey,
            Accept: 'application/json',
          },
          params: {
            ipAddress: ip,
            maxAgeInDays: 90,
          },
          timeout: 10000,
        }),
      );

      const data = response.data.data;
      if (!data) {
        this.logger.warn(`AbuseIPDB returned empty data for IP ${ip}`);
        return null;
      }

      // Flatten and dedupe categories from reports
      const categoriesSet = new Set<number>();
      if (data.reports && Array.isArray(data.reports)) {
        data.reports.forEach((report: any) => {
          if (report.categories && Array.isArray(report.categories)) {
            report.categories.forEach((cat: number) => categoriesSet.add(cat));
          }
        });
      }

      return {
        abuseScore: data.abuseConfidenceScore || 0,
        totalReports: data.totalReports || 0,
        categories: Array.from(categoriesSet),
        countryCode: data.countryCode || 'N/A',
      };
    } catch (error: any) {
      this.logger.warn(`AbuseIPDB check failed for IP ${ip}: ${error.message}`);
      return null;
    }
  }

  async getBlocklist(confidenceMinimum: number = 90): Promise<string[]> {
    if (!this.apiKey) {
      this.logger.warn('AbuseIPDB API key not configured, skipping blocklist fetch');
      return [];
    }

    try {
      const response = await lastValueFrom(
        this.httpService.get('https://api.abuseipdb.com/api/v2/blacklist', {
          headers: {
            Key: this.apiKey,
            Accept: 'application/json',
          },
          params: {
            confidenceMinimum,
            limit: 1000,
          },
          timeout: 10000,
        }),
      );

      const data = response.data.data;
      if (!data || !Array.isArray(data)) {
        this.logger.warn('AbuseIPDB returned invalid blocklist data');
        return [];
      }

      return data.map((entry: any) => entry.ipAddress).filter(Boolean);
    } catch (error: any) {
      this.logger.warn(`AbuseIPDB blocklist fetch failed: ${error.message}`);
      return [];
    }
  }
}
