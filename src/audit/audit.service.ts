import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './entities/audit-log.entity';

@Injectable()
export class AuditService implements OnModuleInit {
  private readonly logger = new Logger(AuditService.name);

  constructor(
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
  ) {}

  async onModuleInit() {
    try {
      // Fix past audit logs created by threat feed / automated actions that have null or empty username
      await this.auditLogRepository
        .createQueryBuilder()
        .update(AuditLog)
        .set({ username: 'system' })
        .where('(username IS NULL OR username = :empty) AND (targetEntity LIKE :abuse OR action LIKE :feed)', {
          empty: '',
          abuse: '%AbuseIPDB%',
          feed: '%Threat Feed%',
        })
        .execute();
    } catch (err: any) {
      this.logger.warn(`Failed to backfill audit log system username: ${err?.message}`);
    }
  }

  async log(
    userId: number | null,
    username: string | null,
    action: string,
    targetEntity?: string,
    ipAddress?: string,
  ): Promise<AuditLog> {
    const effectiveUsername = username || (!userId ? 'system' : undefined);
    const auditLog = this.auditLogRepository.create({
      userId: userId || undefined,
      username: effectiveUsername,
      action,
      targetEntity,
      ipAddress,
    });
    return this.auditLogRepository.save(auditLog);
  }

  async findAll(filters: {
    username?: string;
    action?: string;
    startDate?: string;
    endDate?: string;
  }): Promise<AuditLog[]> {
    const query = this.auditLogRepository.createQueryBuilder('auditLog');

    if (filters.username) {
      query.andWhere('auditLog.username = :username', { username: filters.username });
    }

    if (filters.action) {
      query.andWhere('auditLog.action LIKE :action', { action: `%${filters.action}%` });
    }

    if (filters.startDate) {
      query.andWhere('auditLog.timestamp >= :startDate', { startDate: filters.startDate });
    }

    if (filters.endDate) {
      query.andWhere('auditLog.timestamp <= :endDate', { endDate: filters.endDate });
    }

    query.orderBy('auditLog.timestamp', 'DESC');
    return query.getMany();
  }
}
