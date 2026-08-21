import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { ThreatIntelService } from './threat-intel.service';
import { WhitelistService } from './whitelist.service';
import { BlacklistService } from './blacklist.service';
import { BlockSource } from './entities/blacklist-entry.entity';

@Injectable()
export class ThreatFeedScheduler {
  private readonly logger = new Logger(ThreatFeedScheduler.name);

  constructor(
    private readonly threatIntelService: ThreatIntelService,
    private readonly whitelistService: WhitelistService,
    private readonly blacklistService: BlacklistService,
  ) {}

  @Cron('0 */6 * * *') // every 6 hours
  async syncThreatFeed(): Promise<{
    added: number;
    skipped: number;
    total: number;
  }> {
    return this.performSync(20);
  }

  async performSync(
    limit: number = 20,
  ): Promise<{ added: number; skipped: number; total: number }> {
    this.logger.log(`Starting threat feed sync (limit: ${limit})...`);

    try {
      // Get high-confidence threat IPs from AbuseIPDB with country and score details
      const threatEntries = await this.threatIntelService.getBlocklistDetails(
        95,
        limit,
      );

      if (!threatEntries || threatEntries.length === 0) {
        this.logger.log('No threat IPs found in feed');
        return { added: 0, skipped: 0, total: 0 };
      }

      this.logger.log(
        `Processing ${threatEntries.length} threat IPs from feed`,
      );

      let added = 0;
      let skipped = 0;

      for (const entry of threatEntries) {
        const ip = entry.ipAddress;
        const countryCode = entry.countryCode;
        const abuseScore = entry.abuseConfidenceScore ?? 95;

        try {
          // Skip if whitelisted
          const isWhitelisted = await this.whitelistService.isWhitelisted(ip);
          if (isWhitelisted) {
            this.logger.log(`Skipping whitelisted IP: ${ip}`);
            skipped++;
            continue;
          }

          // If already blacklisted, ensure country code is updated if missing
          const isBlacklisted = await this.blacklistService.isBlacklisted(ip);
          if (isBlacklisted) {
            if (countryCode) {
              await this.blacklistService.updateCountryCodeIfMissing(
                ip,
                countryCode,
              );
            }
            this.logger.log(`Skipping already blacklisted IP: ${ip}`);
            skipped++;
            continue;
          }

          // Block the IP with threat intel data and username 'AbuseIPDB'
          await this.blacklistService.block(
            ip,
            'AbuseIPDB threat feed (confidence >= 95)',
            BlockSource.ABUSEIPDB,
            null,
            'AbuseIPDB',
            { abuseScore, abuseCategories: undefined, countryCode },
          );

          this.logger.log(
            `Added IP to blacklist from threat feed: ${ip} (Country: ${countryCode || 'N/A'})`,
          );
          added++;
        } catch (error: any) {
          this.logger.error(`Failed to process IP ${ip}: ${error.message}`);
          skipped++;
        }
      }

      this.logger.log(
        `Threat feed sync completed: ${added} added, ${skipped} skipped, ${threatEntries.length} total`,
      );
      return { added, skipped, total: threatEntries.length };
    } catch (error: any) {
      this.logger.error(`Threat feed sync failed: ${error.message}`);
      throw error;
    }
  }
}
