import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { lastValueFrom } from 'rxjs';

export interface ThreatBlocklistEntry {
  ipAddress: string;
  countryCode?: string;
  abuseConfidenceScore?: number;
}

export interface AbuseIpDbSourceResult {
  score: number;
  totalReports: number;
  categories: number[];
  countryCode: string;
  isp?: string;
  usageType?: string;
}

export interface VirusTotalSourceResult {
  score: number;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  totalEngines: number;
  asOwner?: string;
  country?: string;
}

export interface AlienVaultSourceResult {
  score: number;
  pulseCount: number;
  pulses?: Array<{ name: string; adversary?: string; tags?: string[] }>;
  countryCode?: string;
}

export interface IpQualityScoreSourceResult {
  score: number;
  isProxy: boolean;
  isVpn: boolean;
  isTor: boolean;
  recentAbuse: boolean;
  botStatus?: boolean;
  isp?: string;
  countryCode?: string;
  city?: string;
  region?: string;
}

export interface ThreatIntelResult {
  ip?: string;
  abuseScore: number;
  compositeScore?: number;
  verdict?: 'clean' | 'suspicious' | 'critical';
  totalReports: number;
  categories: number[];
  countryCode: string;
  countryName?: string;
  city?: string;
  region?: string;
  isp?: string;
  activeSources?: number;
  sources?: {
    abuseipdb?: AbuseIpDbSourceResult;
    virusTotal?: VirusTotalSourceResult;
    alienVault?: AlienVaultSourceResult;
    ipQualityScore?: IpQualityScoreSourceResult;
  };
}

@Injectable()
export class ThreatIntelService {
  private readonly logger = new Logger(ThreatIntelService.name);
  private readonly abuseApiKey: string;
  private readonly vtApiKey: string;
  private readonly otxApiKey: string;
  private readonly ipqsApiKey: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.abuseApiKey = this.configService.get<string>('ABUSEIPDB_API_KEY') || '';
    this.vtApiKey = this.configService.get<string>('VIRUSTOTAL_API_KEY') || '';
    this.otxApiKey = this.configService.get<string>('OTX_API_KEY') || '';
    this.ipqsApiKey = this.configService.get<string>('IPQS_API_KEY') || '';

    this.logger.log(`Threat Intel initialized with providers: [AbuseIPDB: ${Boolean(this.abuseApiKey)}, VirusTotal: ${Boolean(this.vtApiKey)}, OTX: ${Boolean(this.otxApiKey)}, IPQS: ${Boolean(this.ipqsApiKey)}]`);
  }

  isPrivateIp(ip: string): boolean {
    if (!ip) return false;
    const cleanIp = ip.trim();
    if (cleanIp === 'localhost' || cleanIp.startsWith('127.')) return true;
    if (cleanIp.startsWith('10.')) return true;
    if (cleanIp.startsWith('192.168.')) return true;
    if (cleanIp.startsWith('169.254.')) return true; // Link-local / APIPA
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIp)) return true;
    if (cleanIp === '::1' || cleanIp.startsWith('fe80:') || cleanIp.startsWith('fc00:')) return true;
    return false;
  }

  private async checkAbuseIpDb(ip: string): Promise<AbuseIpDbSourceResult | null> {
    if (!this.abuseApiKey) return null;

    try {
      const response = await lastValueFrom(
        this.httpService.get('https://api.abuseipdb.com/api/v2/check', {
          headers: {
            Key: this.abuseApiKey,
            Accept: 'application/json',
          },
          params: {
            ipAddress: ip,
            maxAgeInDays: 90,
          },
          timeout: 8000,
        }),
      );

      const data = response.data?.data;
      if (!data) return null;

      const categoriesSet = new Set<number>();
      if (data.reports && Array.isArray(data.reports)) {
        data.reports.forEach((report: any) => {
          if (report.categories && Array.isArray(report.categories)) {
            report.categories.forEach((cat: number) => categoriesSet.add(cat));
          }
        });
      }

      return {
        score: data.abuseConfidenceScore || 0,
        totalReports: data.totalReports || 0,
        categories: Array.from(categoriesSet),
        countryCode: data.countryCode || 'N/A',
        isp: data.isp,
        usageType: data.usageType,
      };
    } catch (error: any) {
      this.logger.warn(`AbuseIPDB check failed for IP ${ip}: ${error.message}`);
      return null;
    }
  }

  private async checkVirusTotal(ip: string): Promise<VirusTotalSourceResult | null> {
    if (!this.vtApiKey) return null;

    try {
      const response = await lastValueFrom(
        this.httpService.get(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
          headers: {
            'x-apikey': this.vtApiKey,
            Accept: 'application/json',
          },
          timeout: 8000,
        }),
      );

      const attributes = response.data?.data?.attributes;
      if (!attributes) return null;

      const stats = attributes.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;
      const totalEngines = malicious + suspicious + harmless + undetected || 1;

      // Normalization: 5+ malicious = 100%, 2-4 = 75%, 1 = 40%, suspicious = 20%
      let score = 0;
      if (malicious >= 5) score = 100;
      else if (malicious >= 2) score = 75;
      else if (malicious === 1) score = 40;
      else if (suspicious > 0) score = Math.min(30, suspicious * 10);

      return {
        score,
        malicious,
        suspicious,
        harmless,
        undetected,
        totalEngines,
        asOwner: attributes.as_owner || attributes.network,
        country: attributes.country,
      };
    } catch (error: any) {
      this.logger.warn(`VirusTotal check failed for IP ${ip}: ${error.message}`);
      return null;
    }
  }

  private async checkAlienVault(ip: string): Promise<AlienVaultSourceResult | null> {
    try {
      const headers: Record<string, string> = { Accept: 'application/json' };
      if (this.otxApiKey) headers['X-OTX-API-KEY'] = this.otxApiKey;

      const response = await lastValueFrom(
        this.httpService.get(`https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(ip)}/general`, {
          headers,
          timeout: 8000,
        }),
      );

      const data = response.data;
      if (!data) return null;

      const pulseCount = data.pulse_info?.count || 0;
      const rawPulses = data.pulse_info?.pulses || [];
      const pulses = rawPulses.slice(0, 5).map((p: any) => ({
        name: p.name,
        adversary: p.adversary || undefined,
        tags: Array.isArray(p.tags) ? p.tags.slice(0, 4) : [],
      }));

      // Normalization: 5+ pulses = 100%, 3-4 = 80%, 1-2 = 60%, 0 = 0%
      let score = 0;
      if (pulseCount >= 5) score = 100;
      else if (pulseCount >= 3) score = 80;
      else if (pulseCount >= 1) score = 60;

      return {
        score,
        pulseCount,
        pulses,
        countryCode: data.country_code,
      };
    } catch (error: any) {
      this.logger.warn(`AlienVault OTX check failed for IP ${ip}: ${error.message}`);
      return null;
    }
  }

  private async checkIpQualityScore(ip: string): Promise<IpQualityScoreSourceResult | null> {
    if (!this.ipqsApiKey) return null;

    try {
      const response = await lastValueFrom(
        this.httpService.get(`https://ipqualityscore.com/api/json/ip/${this.ipqsApiKey}/${encodeURIComponent(ip)}`, {
          params: { strictness: 1 },
          timeout: 8000,
        }),
      );

      const data = response.data;
      if (!data || data.success === false) return null;

      const score = Math.min(100, Math.max(0, data.fraud_score || 0));

      return {
        score,
        isProxy: Boolean(data.proxy),
        isVpn: Boolean(data.vpn || data.active_vpn),
        isTor: Boolean(data.tor || data.active_tor),
        recentAbuse: Boolean(data.recent_abuse),
        botStatus: Boolean(data.bot_status),
        isp: data.ISP,
        countryCode: data.country_code,
        city: data.city || undefined,
        region: data.region || undefined,
      };
    } catch (error: any) {
      this.logger.warn(`IPQualityScore check failed for IP ${ip}: ${error.message}`);
      return null;
    }
  }

  async checkIp(ip: string): Promise<ThreatIntelResult | null> {
    if (!ip) return null;

    if (this.isPrivateIp(ip)) {
      return {
        ip,
        abuseScore: 0,
        compositeScore: 0,
        verdict: 'clean',
        totalReports: 0,
        categories: [],
        countryCode: 'Local (LAN)',
        countryName: 'Local Network',
        isp: 'Private Network',
        activeSources: 0,
        sources: {},
      };
    }

    // Run active providers in parallel
    const [abuseRes, vtRes, otxRes, ipqsRes] = await Promise.allSettled([
      this.checkAbuseIpDb(ip),
      this.checkVirusTotal(ip),
      this.checkAlienVault(ip),
      this.checkIpQualityScore(ip),
    ]);

    const sources: ThreatIntelResult['sources'] = {};
    const scores: number[] = [];

    let resolvedCountry = 'N/A';
    let resolvedIsp: string | undefined;
    let resolvedCity: string | undefined;
    let resolvedRegion: string | undefined;

    if (abuseRes.status === 'fulfilled' && abuseRes.value) {
      sources.abuseipdb = abuseRes.value;
      scores.push(abuseRes.value.score);
      if (abuseRes.value.countryCode && abuseRes.value.countryCode !== 'N/A') {
        resolvedCountry = abuseRes.value.countryCode;
      }
      if (abuseRes.value.isp) resolvedIsp = abuseRes.value.isp;
    }

    if (vtRes.status === 'fulfilled' && vtRes.value) {
      sources.virusTotal = vtRes.value;
      scores.push(vtRes.value.score);
      if (vtRes.value.country && resolvedCountry === 'N/A') {
        resolvedCountry = vtRes.value.country;
      }
      if (vtRes.value.asOwner && !resolvedIsp) resolvedIsp = vtRes.value.asOwner;
    }

    if (otxRes.status === 'fulfilled' && otxRes.value) {
      sources.alienVault = otxRes.value;
      scores.push(otxRes.value.score);
      if (otxRes.value.countryCode && resolvedCountry === 'N/A') {
        resolvedCountry = otxRes.value.countryCode;
      }
    }

    if (ipqsRes.status === 'fulfilled' && ipqsRes.value) {
      sources.ipQualityScore = ipqsRes.value;
      scores.push(ipqsRes.value.score);
      if (ipqsRes.value.countryCode && resolvedCountry === 'N/A') {
        resolvedCountry = ipqsRes.value.countryCode;
      }
      if (ipqsRes.value.isp && !resolvedIsp) resolvedIsp = ipqsRes.value.isp;
      if (ipqsRes.value.city) resolvedCity = ipqsRes.value.city;
      if (ipqsRes.value.region) resolvedRegion = ipqsRes.value.region;
    }

    // If no provider responded or configured
    if (scores.length === 0) {
      return null;
    }

    // Calculate composite score as average of active providers
    const compositeScore = Math.round(scores.reduce((sum, s) => sum + s, 0) / scores.length);

    let verdict: 'clean' | 'suspicious' | 'critical' = 'clean';
    if (compositeScore >= 60 || (sources.virusTotal?.malicious && sources.virusTotal.malicious >= 3)) {
      verdict = 'critical';
    } else if (compositeScore >= 25 || (sources.virusTotal?.malicious && sources.virusTotal.malicious >= 1)) {
      verdict = 'suspicious';
    }

    return {
      ip,
      abuseScore: compositeScore,
      compositeScore,
      verdict,
      totalReports: sources.abuseipdb?.totalReports || 0,
      categories: sources.abuseipdb?.categories || [],
      countryCode: resolvedCountry,
      city: resolvedCity,
      region: resolvedRegion,
      isp: resolvedIsp,
      activeSources: scores.length,
      sources,
    };
  }

  async getBlocklistDetails(confidenceMinimum: number = 90, limit: number = 20): Promise<ThreatBlocklistEntry[]> {
    if (!this.abuseApiKey) {
      this.logger.warn('AbuseIPDB API key not configured, skipping blocklist fetch');
      return [];
    }

    const effectiveLimit = Math.max(1, limit || parseInt(this.configService.get<string>('ABUSEIPDB_LIMIT') || '20', 10) || 20);

    try {
      const response = await lastValueFrom(
        this.httpService.get('https://api.abuseipdb.com/api/v2/blacklist', {
          headers: {
            Key: this.abuseApiKey,
            Accept: 'application/json',
          },
          params: {
            confidenceMinimum,
            limit: effectiveLimit,
          },
          timeout: 10000,
        }),
      );

      const data = response.data?.data;
      if (!data || !Array.isArray(data)) {
        this.logger.warn('AbuseIPDB returned invalid blocklist data');
        return [];
      }

      return data
        .filter((entry: any) => Boolean(entry?.ipAddress))
        .slice(0, effectiveLimit)
        .map((entry: any) => ({
          ipAddress: entry.ipAddress,
          countryCode: entry.countryCode && entry.countryCode !== 'N/A' && entry.countryCode !== 'n/a' ? entry.countryCode : undefined,
          abuseConfidenceScore: entry.abuseConfidenceScore || confidenceMinimum,
        }));
    } catch (error: any) {
      this.logger.warn(`AbuseIPDB blocklist fetch failed: ${error.message}`);
      return [];
    }
  }

  async getBlocklist(confidenceMinimum: number = 90, limit: number = 20): Promise<string[]> {
    const details = await this.getBlocklistDetails(confidenceMinimum, limit);
    return details.map((entry) => entry.ipAddress);
  }
}
