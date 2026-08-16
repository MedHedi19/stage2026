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
  async syncThreatFeed(): Promise<{ added: number; skipped: number; total: number }> {
    return this.performSync();
  }

  async performSync(): Promise<{ added: number; skipped: number; total: number }> {
    this.logger.log('Starting threat feed sync...');
    
    try {
      // Get high-confidence threat IPs from AbuseIPDB
      const threatIps = await this.threatIntelService.getBlocklist(95);
      
      if (!threatIps || threatIps.length === 0) {
        this.logger.log('No threat IPs found in feed');
        return { added: 0, skipped: 0, total: 0 };
      }

      this.logger.log(`Processing ${threatIps.length} threat IPs from feed`);

      let added = 0;
      let skipped = 0;

      for (const ip of threatIps) {
        try {
          // Skip if whitelisted
          const isWhitelisted = await this.whitelistService.isWhitelisted(ip);
          if (isWhitelisted) {
            this.logger.log(`Skipping whitelisted IP: ${ip}`);
            skipped++;
            continue;
          }

          // Skip if already blacklisted
          const isBlacklisted = await this.blacklistService.isBlacklisted(ip);
          if (isBlacklisted) {
            this.logger.log(`Skipping already blacklisted IP: ${ip}`);
            skipped++;
            continue;
          }

          // Block the IP with threat intel data
          await this.blacklistService.block(
            ip,
            'AbuseIPDB threat feed (confidence >= 95)',
            BlockSource.AUTO,
            null,
            null,
            { abuseScore: 95, abuseCategories: undefined },
          );

          this.logger.log(`Added IP to blacklist from threat feed: ${ip}`);
          added++;
        } catch (error: any) {
          this.logger.error(`Failed to process IP ${ip}: ${error.message}`);
          skipped++;
        }
      }

      this.logger.log(`Threat feed sync completed: ${added} added, ${skipped} skipped, ${threatIps.length} total`);
      return { added, skipped, total: threatIps.length };
    } catch (error: any) {
      this.logger.error(`Threat feed sync failed: ${error.message}`);
      throw error;
    }
  }
}
