import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import { BlacklistEntry, BlockSource } from './entities/blacklist-entry.entity';
import { FirewallService } from './firewall.service';
import { AuditService } from '../audit/audit.service';
import { FirewallHistoryService } from './firewall-history.service';
import { FirewallListType, FirewallAction } from './entities/firewall-history.entity';
import { ThreatIntelService } from './threat-intel.service';

@Injectable()
export class BlacklistService {
  private readonly logger = new Logger(BlacklistService.name);

  constructor(
    @InjectRepository(BlacklistEntry)
    private blacklistRepository: Repository<BlacklistEntry>,
    private readonly firewallService: FirewallService,
    private readonly auditService: AuditService,
    private readonly historyService: FirewallHistoryService,
    private readonly threatIntelService: ThreatIntelService,
  ) {}

  /**
   * Block an IP address
   * @param ip - IP address to block
   * @param reason - Reason for blocking
   * @param source - Source of block ('auto' or 'manual')
   * @param userId - User ID who initiated the block (null for auto)
   * @param username - Username who initiated the block (null for auto)
   * @param threatData - Optional threat intelligence data from AbuseIPDB
   * @returns The blacklist entry (existing if already blocked, new if just blocked)
   */
  async block(
    ip: string,
    reason: string,
    source: BlockSource,
    userId: number | null,
    username: string | null,
    threatData?: { abuseScore?: number; abuseCategories?: string; countryCode?: string },
  ): Promise<BlacklistEntry> {
    const effectiveUsername = username || 'system';

    // If threatData or countryCode is missing, attempt quick lookup
    let finalCountryCode = threatData?.countryCode ?? null;
    let finalAbuseScore = threatData?.abuseScore ?? null;
    let finalAbuseCategories = threatData?.abuseCategories ?? null;

    if (!finalCountryCode && ip) {
      try {
        const intel = await this.threatIntelService.checkIp(ip);
        if (intel && intel.countryCode && intel.countryCode !== 'N/A' && intel.countryCode !== 'n/a') {
          finalCountryCode = intel.countryCode;
          if (finalAbuseScore === null) finalAbuseScore = intel.abuseScore;
        }
      } catch (err) {
        // non-fatal
      }
    }

    // Check for ANY existing entry for this IP (regardless of active status)
    const anyExistingEntry = await this.blacklistRepository.findOne({
      where: { ip },
    });

    if (anyExistingEntry) {
      if (anyExistingEntry.active) {
        // If missing country code, update it
        if (!anyExistingEntry.countryCode && finalCountryCode) {
          try {
            anyExistingEntry.countryCode = finalCountryCode;
            if (finalAbuseScore !== null) anyExistingEntry.abuseScore = finalAbuseScore;
            await this.blacklistRepository.save(anyExistingEntry);
          } catch (err: any) {
            this.logger.warn(`Failed to update threatData for existing active IP ${ip}: ${err.message}`);
          }
        }
        this.logger.log(`IP ${ip} is already blacklisted, returning existing entry`);
        return anyExistingEntry;
      } else {
        // Inactive (was previously unblocked) - reactivate it
        try {
          await this.firewallService.addToSet('blacklist', ip);
        } catch (error: any) {
          this.logger.error(`Failed to add IP ${ip} to firewall blacklist: ${error.message}`);
          throw error;
        }

        // Update existing row core fields first
        anyExistingEntry.active = true;
        anyExistingEntry.reason = reason;
        anyExistingEntry.source = source;
        anyExistingEntry.addedBy = effectiveUsername;
        anyExistingEntry.createdAt = new Date();

        let savedEntry = await this.blacklistRepository.save(anyExistingEntry);
        this.logger.log(`Re-activated blocked IP ${ip} (source: ${source}, reason: ${reason})`);

        // Separate threatData save step
        if (finalAbuseScore !== null || finalAbuseCategories !== null || finalCountryCode !== null) {
          try {
            savedEntry.abuseScore = finalAbuseScore ?? savedEntry.abuseScore;
            savedEntry.abuseCategories = finalAbuseCategories ?? savedEntry.abuseCategories;
            savedEntry.countryCode = finalCountryCode ?? savedEntry.countryCode;
            savedEntry = await this.blacklistRepository.save(savedEntry);
          } catch (err: any) {
            this.logger.warn(`Failed to update threatData for re-activated IP ${ip}: ${err.message}`);
          }
        }

        await this.auditService.log(userId, effectiveUsername, 'Add to Blacklist', `${ip} - Reason: ${reason}`, ip);
        await this.historyService.record(FirewallListType.BLACKLIST, FirewallAction.ADD, ip, reason, effectiveUsername);
        return savedEntry;
      }
    }

    // Add to firewall ipset
    try {
      await this.firewallService.addToSet('blacklist', ip);
    } catch (error: any) {
      this.logger.error(`Failed to add IP ${ip} to firewall blacklist: ${error.message}`);
      throw error; // Rethrow - do NOT save DB row if firewall fails
    }

    // Save core block row immediately
    const entry = this.blacklistRepository.create({
      ip,
      reason,
      source,
      addedBy: effectiveUsername,
      active: true,
    });

    let savedEntry = await this.blacklistRepository.save(entry);
    this.logger.log(`Blocked IP ${ip} (source: ${source}, reason: ${reason})`);

    // Separate threatData save step
    if (finalAbuseScore !== null || finalAbuseCategories !== null || finalCountryCode !== null) {
      try {
        savedEntry.abuseScore = finalAbuseScore;
        savedEntry.abuseCategories = finalAbuseCategories;
        savedEntry.countryCode = finalCountryCode;
        savedEntry = await this.blacklistRepository.save(savedEntry);
      } catch (err: any) {
        this.logger.warn(`Failed to save threatData for blocked IP ${ip}: ${err.message}`);
      }
    }

    // Audit log
    await this.auditService.log(userId, effectiveUsername, 'Add to Blacklist', `${ip} - Reason: ${reason}`, ip);
    await this.historyService.record(FirewallListType.BLACKLIST, FirewallAction.ADD, ip, reason, effectiveUsername);

    return savedEntry;
  }

  /**
   * Unblock an IP address
   * @param ip - IP address to unblock
   * @param userId - User ID who initiated the unblock
   * @param username - Username who initiated the unblock
   */
  async unblock(ip: string, userId: number, username: string): Promise<void> {
    // Fetch the entry to get the reason before unblocking
    const entry = await this.blacklistRepository.findOne({ where: { ip, active: true } });
    const reason = entry?.reason || 'Unknown';

    // Remove from firewall ipset (tolerant of failures)
    try {
      await this.firewallService.removeFromSet('blacklist', ip);
    } catch (error: any) {
      this.logger.warn(`Failed to remove IP ${ip} from firewall blacklist (continuing): ${error.message}`);
      // Continue - DB state is more important than ipset state
    }

    // Update database entries to inactive
    const result = await this.blacklistRepository.update(
      { ip, active: true },
      { active: false },
    );

    this.logger.log(`Unblocked IP ${ip}, updated ${result.affected} entries`);

    // Audit log
    await this.auditService.log(userId, username, 'Remove from Blacklist', `${ip} - Reason: ${reason}`, ip);
    await this.historyService.record(FirewallListType.BLACKLIST, FirewallAction.REMOVE, ip, reason, username ?? 'system');
  }

  /**
   * Purge all active blacklist entries.
   * @returns Array of IPs that were removed from the blacklist.
   */
  async purgeAll(userId: number, username: string): Promise<string[]> {
    const entries = await this.blacklistRepository.find({ where: { active: true } });
    const ips = entries.map((entry) => entry.ip);

    for (const ip of ips) {
      try {
        await this.firewallService.removeFromSet('blacklist', ip);
      } catch (error: any) {
        this.logger.warn(`Failed to remove IP ${ip} from firewall blacklist during purge (continuing): ${error.message}`);
      }
    }

    if (ips.length > 0) {
      await this.blacklistRepository.update({ active: true }, { active: false });
      await this.auditService.log(userId, username, 'Purge Blacklist', `Purged ${ips.length} blacklist entries`, ips.join(','));
      for (const ip of ips) {
        await this.historyService.record(FirewallListType.BLACKLIST, FirewallAction.PURGE, ip, 'Purge all', username ?? 'system');
      }
    }

    this.logger.log(`Purged ${ips.length} blacklist entries`);
    return ips;
  }

  /**
   * List all active blacklist entries
   * @param page Page number (default: 1)
   * @param limit Items per page (default: 30)
   * @param search Optional search term for IP addresses
   * @returns Array of active blacklist entries ordered by createdAt DESC
   */
  async list(page: number = 1, limit: number = 30, search?: string): Promise<BlacklistEntry[]> {
    const skip = (page - 1) * limit;
    const where: any = { active: true };
    if (search) {
      where.ip = search;
    }
    return this.blacklistRepository.find({
      where,
      order: { createdAt: 'DESC' },
      skip,
      take: limit,
    });
  }

  /**
   * Check if an IP is blacklisted
   * @param ip - IP address to check
   * @returns true if IP is blacklisted, false otherwise
   */
  async isBlacklisted(ip: string): Promise<boolean> {
    const count = await this.blacklistRepository.count({
      where: { ip, active: true },
    });
    return count > 0;
  }

  /**
   * Count total active blacklist entries
   * @param search Optional search term for IP addresses
   * @returns Total count of active blacklist entries
   */
  async count(search?: string): Promise<number> {
    const where: any = { active: true };
    if (search) {
      where.ip = search;
    }
    return this.blacklistRepository.count({ where });
  }

  /**
   * Update country code for an IP if currently missing
   */
  async updateCountryCodeIfMissing(ip: string, countryCode: string): Promise<void> {
    if (!countryCode || countryCode === 'N/A' || countryCode === 'n/a') return;
    await this.blacklistRepository.update(
      { ip, countryCode: IsNull() },
      { countryCode },
    );
  }

  /**
   * Get country statistics from blacklist entries
   * @returns Array of country codes with their counts
   */
  async getCountryStats(): Promise<{ countryCode: string; count: number }[]> {
    const entries = await this.blacklistRepository.find({
      where: { active: true },
      select: { id: true, ip: true, countryCode: true },
    } as any);

    const countryCounts: Record<string, number> = {};
    const missingCountryEntries = entries.filter(
      (e) => !e.countryCode || e.countryCode === 'N/A' || e.countryCode === 'n/a',
    );

    // If entries exist but country codes are missing, perform quick bulk backfill
    if (missingCountryEntries.length > 0) {
      try {
        const threatEntries = await this.threatIntelService.getBlocklistDetails(90);
        const map = new Map<string, { countryCode?: string; abuseScore?: number }>();
        for (const item of threatEntries) {
          if (item.countryCode) {
            map.set(item.ipAddress, { countryCode: item.countryCode, abuseScore: item.abuseConfidenceScore });
          }
        }

        for (const entry of missingCountryEntries) {
          if (this.threatIntelService.isPrivateIp(entry.ip)) {
            entry.countryCode = 'Local (LAN)';
            await this.blacklistRepository.update(entry.id, { countryCode: 'Local (LAN)' });
            continue;
          }

          const matched = map.get(entry.ip);
          if (matched?.countryCode) {
            entry.countryCode = matched.countryCode;
            await this.blacklistRepository.update(entry.id, {
              countryCode: matched.countryCode,
              ...(matched.abuseScore ? { abuseScore: matched.abuseScore } : {}),
            });
          }
        }

        // For any remaining missing entries (up to 15), do individual check
        const stillMissing = missingCountryEntries.filter(
          (e) => !e.countryCode || e.countryCode === 'N/A' || e.countryCode === 'n/a',
        ).slice(0, 15);

        for (const entry of stillMissing) {
          try {
            const threatInfo = await this.threatIntelService.checkIp(entry.ip);
            if (threatInfo && threatInfo.countryCode && threatInfo.countryCode !== 'N/A') {
              entry.countryCode = threatInfo.countryCode;
              await this.blacklistRepository.update(entry.id, {
                countryCode: threatInfo.countryCode,
                abuseScore: threatInfo.abuseScore,
              });
            }
          } catch (e) {
            // ignore
          }
        }
      } catch (err: any) {
        this.logger.warn(`Failed to backfill country codes during getCountryStats: ${err?.message}`);
      }
    }

    for (const entry of entries) {
      if (entry.countryCode && entry.countryCode !== 'N/A' && entry.countryCode !== 'n/a') {
        countryCounts[entry.countryCode] = (countryCounts[entry.countryCode] || 0) + 1;
      }
    }

    return Object.entries(countryCounts)
      .map(([countryCode, count]) => ({ countryCode, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Backfill country codes for existing blacklist entries without country data
   * Uses fast bulk matching from AbuseIPDB threat feed first, then individual lookups
   * @returns Number of entries updated
   */
  async backfillCountryCodes(): Promise<number> {
    let updated = 0;

    try {
      // 1. Fast bulk match from threat feed blocklist (1 HTTP call for 1000 IPs)
      const threatEntries = await this.threatIntelService.getBlocklistDetails(90);
      const map = new Map<string, { countryCode?: string; abuseScore?: number }>();
      for (const item of threatEntries) {
        if (item.countryCode) {
          map.set(item.ipAddress, { countryCode: item.countryCode, abuseScore: item.abuseConfidenceScore });
        }
      }

      const entriesWithoutCountry = await this.blacklistRepository.find({
        where: { active: true, countryCode: IsNull() },
        select: { id: true, ip: true },
      } as any);

      for (const entry of entriesWithoutCountry) {
        const matched = map.get(entry.ip);
        if (matched?.countryCode) {
          await this.blacklistRepository.update(entry.id, {
            countryCode: matched.countryCode,
            ...(matched.abuseScore ? { abuseScore: matched.abuseScore } : {}),
          });
          updated++;
        }
      }

      // 2. For remaining unmatched entries, check individually up to 20
      const remaining = await this.blacklistRepository.find({
        where: { active: true, countryCode: IsNull() },
        take: 20,
        select: { id: true, ip: true },
      } as any);

      for (const entry of remaining) {
        try {
          const threatInfo = await this.threatIntelService.checkIp(entry.ip);
          if (threatInfo && threatInfo.countryCode && threatInfo.countryCode !== 'N/A') {
            await this.blacklistRepository.update(entry.id, {
              countryCode: threatInfo.countryCode,
              abuseScore: threatInfo.abuseScore,
            });
            updated++;
          }
        } catch (error) {
          // ignore
        }
      }
    } catch (error: any) {
      this.logger.error(`backfillCountryCodes failed: ${error.message}`);
    }

    return updated;
  }
}
