import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  FirewallHistory,
  FirewallListType,
  FirewallAction,
} from './entities/firewall-history.entity';

@Injectable()
export class FirewallHistoryService {
  constructor(
    @InjectRepository(FirewallHistory)
    private readonly historyRepo: Repository<FirewallHistory>,
  ) {}

  /**
   * Record a firewall list operation.
   */
  async record(
    listType: FirewallListType,
    action: FirewallAction,
    ip: string,
    reason: string | null,
    performedBy: string,
  ): Promise<FirewallHistory> {
    const entry = this.historyRepo.create({
      listType,
      action,
      ip,
      reason: reason ?? undefined,
      performedBy,
    });
    return this.historyRepo.save(entry);
  }

  /**
   * Get history entries, optionally filtered by list type and limited.
   * @param listType - 'blacklist' | 'whitelist' | undefined (all)
   * @param limit - max number of entries to return (undefined = all)
   */
  async getHistory(
    listType?: FirewallListType,
    limit?: number,
  ): Promise<FirewallHistory[]> {
    const qb = this.historyRepo
      .createQueryBuilder('h')
      .orderBy('h.createdAt', 'DESC');

    if (listType) {
      qb.where('h.listType = :listType', { listType });
    }

    if (limit && limit > 0) {
      qb.take(limit);
    }

    return qb.getMany();
  }
}
