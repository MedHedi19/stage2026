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
    // Check for ANY existing entry for this IP (regardless of active status)
    const anyExistingEntry = await this.blacklistRepository.findOne({
      where: { ip },
    });

    if (anyExistingEntry) {
      if (anyExistingEntry.active) {
        // Already active - return unchanged (idempotent)
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

        // Update existing row instead of creating new one
        anyExistingEntry.active = true;
        anyExistingEntry.reason = reason;
        anyExistingEntry.source = source;
        anyExistingEntry.addedBy = username ?? 'system';
        anyExistingEntry.createdAt = new Date();
        if (threatData) {
          anyExistingEntry.abuseScore = threatData.abuseScore ?? null;
          anyExistingEntry.abuseCategories = threatData.abuseCategories ?? null;
          anyExistingEntry.countryCode = threatData.countryCode ?? null;
        }

        const savedEntry = await this.blacklistRepository.save(anyExistingEntry);
        this.logger.log(`Re-activated blocked IP ${ip} (source: ${source}, reason: ${reason})`);

        await this.auditService.log(userId, username, 'Add to Blacklist', `${ip} - Reason: ${reason}`, ip);
        await this.historyService.record(FirewallListType.BLACKLIST, FirewallAction.ADD, ip, reason, username ?? 'system');
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

    // Save to database
    const entry = this.blacklistRepository.create({
      ip,
      reason,
      source,
      addedBy: username ?? 'system',
      active: true,
      abuseScore: threatData?.abuseScore ?? null,
      abuseCategories: threatData?.abuseCategories ?? null,
      countryCode: threatData?.countryCode ?? null,
    });

    const savedEntry = await this.blacklistRepository.save(entry);
    this.logger.log(`Blocked IP ${ip} (source: ${source}, reason: ${reason})`);

    // Audit log
    await this.auditService.log(userId, username, 'Add to Blacklist', `${ip} - Reason: ${reason}`, ip);
    await this.historyService.record(FirewallListType.BLACKLIST, FirewallAction.ADD, ip, reason, username ?? 'system');

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
   * Get country statistics from blacklist entries
   * @returns Array of country codes with their counts
   */
  async getCountryStats(): Promise<{ countryCode: string; count: number }[]> {
    const entries = await this.blacklistRepository.find({
      where: { active: true },
      select: { countryCode: true },
    } as any);

    const countryCounts: Record<string, number> = {};

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
   * This is a maintenance operation to update old entries with AbuseIPDB country data
   * @returns Number of entries updated
   */
  async backfillCountryCodes(): Promise<number> {
    const entriesWithoutCountry = await this.blacklistRepository.find({
      where: { active: true, countryCode: IsNull() },
      select: { id: true, ip: true },
    } as any);

    let updated = 0;
    for (const entry of entriesWithoutCountry) {
      try {
        const threatInfo = await this.threatIntelService.checkIp(entry.ip);
        if (threatInfo && threatInfo.countryCode) {
          await this.blacklistRepository.update(entry.id, {
            countryCode: threatInfo.countryCode,
          });
          updated++;
        }
      } catch (error) {
        console.error(`Failed to fetch country for ${entry.ip}:`, error);
      }
    }

    return updated;
  }
}
