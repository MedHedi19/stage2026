import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './entities/audit-log.entity';

@Injectable()
export class AuditService {
  constructor(
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
  ) {}

  async log(
    userId: number | null,
    username: string | null,
    action: string,
    targetEntity?: string,
    ipAddress?: string,
  ): Promise<AuditLog> {
    const auditLog = this.auditLogRepository.create({
      userId: userId || undefined,
      username: username || undefined,
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
