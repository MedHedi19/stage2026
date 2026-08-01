import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { BlacklistEntry, BlockSource } from './entities/blacklist-entry.entity';
import { FirewallService } from './firewall.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class BlacklistService {
  private readonly logger = new Logger(BlacklistService.name);

  constructor(
    @InjectRepository(BlacklistEntry)
    private blacklistRepository: Repository<BlacklistEntry>,
    private readonly firewallService: FirewallService,
    private readonly auditService: AuditService,
  ) {}

  /**
   * Block an IP address
   * @param ip - IP address to block
   * @param reason - Reason for blocking
   * @param source - Source of block ('auto' or 'manual')
   * @param userId - User ID who initiated the block (null for auto)
   * @param username - Username who initiated the block (null for auto)
   * @returns The blacklist entry (existing if already blocked, new if just blocked)
   */
  async block(
    ip: string,
    reason: string,
    source: BlockSource,
    userId: number | null,
    username: string | null,
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

        const savedEntry = await this.blacklistRepository.save(anyExistingEntry);
        this.logger.log(`Re-activated blocked IP ${ip} (source: ${source}, reason: ${reason})`);

        await this.auditService.log(userId, username, 'Add to Blacklist', `${ip} - Reason: ${reason}`, ip);
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
    });

    const savedEntry = await this.blacklistRepository.save(entry);
    this.logger.log(`Blocked IP ${ip} (source: ${source}, reason: ${reason})`);

    // Audit log
    await this.auditService.log(userId, username, 'Add to Blacklist', `${ip} - Reason: ${reason}`, ip);

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
  }

  /**
   * List all active blacklist entries
   * @returns Array of active blacklist entries ordered by createdAt DESC
   */
  async list(): Promise<BlacklistEntry[]> {
    return this.blacklistRepository.find({
      where: { active: true },
      order: { createdAt: 'DESC' },
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
}
