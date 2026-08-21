import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { WhitelistEntry } from './entities/whitelist-entry.entity';
import { FirewallService } from './firewall.service';
import { AuditService } from '../audit/audit.service';
import { FirewallHistoryService } from './firewall-history.service';
import {
  FirewallListType,
  FirewallAction,
} from './entities/firewall-history.entity';

@Injectable()
export class WhitelistService {
  private readonly logger = new Logger(WhitelistService.name);

  constructor(
    @InjectRepository(WhitelistEntry)
    private whitelistRepository: Repository<WhitelistEntry>,
    private readonly firewallService: FirewallService,
    private readonly auditService: AuditService,
    private readonly historyService: FirewallHistoryService,
  ) {}

  /**
   * Add an IP to whitelist
   * @param ip - IP address to whitelist
   * @param reason - Reason for whitelisting
   * @param userId - User ID who initiated the add
   * @param username - Username who initiated the add
   * @returns The whitelist entry (existing if already whitelisted, new if just added)
   */
  async add(
    ip: string,
    reason: string,
    userId: number,
    username: string,
  ): Promise<WhitelistEntry> {
    // Check if IP is already whitelisted (idempotent)
    const existingEntry = await this.whitelistRepository.findOne({
      where: { ip },
    });

    if (existingEntry) {
      this.logger.log(
        `IP ${ip} is already whitelisted, returning existing entry`,
      );
      return existingEntry;
    }

    // Add to firewall ipset
    try {
      await this.firewallService.addToSet('whitelist', ip);
    } catch (error: any) {
      this.logger.error(
        `Failed to add IP ${ip} to firewall whitelist: ${error.message}`,
      );
      throw error; // Rethrow - do NOT save DB row if firewall fails
    }

    // Save to database
    const entry = this.whitelistRepository.create({
      ip,
      reason,
      addedBy: username,
    });

    const savedEntry = await this.whitelistRepository.save(entry);
    this.logger.log(`Whitelisted IP ${ip} (reason: ${reason})`);

    // Audit log
    await this.auditService.log(
      userId,
      username,
      'Add to Whitelist',
      `${ip} - Reason: ${reason}`,
      ip,
    );
    await this.historyService.record(
      FirewallListType.WHITELIST,
      FirewallAction.ADD,
      ip,
      reason,
      username,
    );

    return savedEntry;
  }

  /**
   * Remove an IP from whitelist
   * @param ip - IP address to remove
   * @param userId - User ID who initiated the removal
   * @param username - Username who initiated the removal
   */
  async remove(ip: string, userId: number, username: string): Promise<void> {
    // Fetch the entry to get the reason before removing
    const entry = await this.whitelistRepository.findOne({ where: { ip } });
    const reason = entry?.reason || 'Unknown';

    // Remove from firewall ipset (tolerant of failures)
    try {
      await this.firewallService.removeFromSet('whitelist', ip);
    } catch (error: any) {
      this.logger.warn(
        `Failed to remove IP ${ip} from firewall whitelist (continuing): ${error.message}`,
      );
      // Continue - DB state is more important than ipset state
    }

    // Delete from database
    const result = await this.whitelistRepository.delete({ ip });

    this.logger.log(
      `Removed IP ${ip} from whitelist, deleted ${result.affected} entries`,
    );

    // Audit log
    await this.auditService.log(
      userId,
      username,
      'Remove from Whitelist',
      `${ip} - Reason: ${reason}`,
      ip,
    );
    await this.historyService.record(
      FirewallListType.WHITELIST,
      FirewallAction.REMOVE,
      ip,
      reason,
      username,
    );
  }

  /**
   * Purge all whitelist entries.
   * @returns Array of IPs that were removed from the whitelist.
   */
  async purgeAll(userId: number, username: string): Promise<string[]> {
    const entries = await this.whitelistRepository.find();
    const ips = entries.map((entry) => entry.ip);

    for (const ip of ips) {
      try {
        await this.firewallService.removeFromSet('whitelist', ip);
      } catch (error: any) {
        this.logger.warn(
          `Failed to remove IP ${ip} from firewall whitelist during purge (continuing): ${error.message}`,
        );
      }
    }

    if (ips.length > 0) {
      await this.whitelistRepository.clear();
      await this.auditService.log(
        userId,
        username,
        'Purge Whitelist',
        `Purged ${ips.length} whitelist entries`,
        ips.join(','),
      );
      for (const ip of ips) {
        await this.historyService.record(
          FirewallListType.WHITELIST,
          FirewallAction.PURGE,
          ip,
          'Purge all',
          username,
        );
      }
    }

    this.logger.log(`Purged ${ips.length} whitelist entries`);
    return ips;
  }

  /**
   * List all whitelist entries
   * @param page Page number (default: 1)
   * @param limit Items per page (default: 30)
   * @param search Optional search term for IP addresses
   * @returns Array of whitelist entries ordered by createdAt DESC
   */
  async list(
    page: number = 1,
    limit: number = 30,
    search?: string,
  ): Promise<WhitelistEntry[]> {
    const skip = (page - 1) * limit;
    const where: any = {};
    if (search) {
      where.ip = search;
    }
    return this.whitelistRepository.find({
      where,
      order: { createdAt: 'DESC' },
      skip,
      take: limit,
    });
  }

  /**
   * Check if an IP is whitelisted
   * @param ip - IP address to check
   * @returns true if IP is whitelisted, false otherwise
   */
  async isWhitelisted(ip: string): Promise<boolean> {
    const count = await this.whitelistRepository.count({
      where: { ip },
    });
    return count > 0;
  }

  /**
   * Count total whitelist entries
   * @param search Optional search term for IP addresses
   * @returns Total count of whitelist entries
   */
  async count(search?: string): Promise<number> {
    const where: any = {};
    if (search) {
      where.ip = search;
    }
    return this.whitelistRepository.count({ where });
  }
}
