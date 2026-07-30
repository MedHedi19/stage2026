import { Controller, Get, Post, Delete, Body, Param, UseGuards, Request, UseInterceptors } from '@nestjs/common';
import { BlacklistService } from './blacklist.service';
import { WhitelistService } from './whitelist.service';
import { BlockSource } from './entities/blacklist-entry.entity';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from '../users/entities/user.entity';
import { AuditAction } from '../audit/audit-action.decorator';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';
import { AddIpDto } from './dto/add-ip.dto';

@Controller('ips')
@UseGuards(JwtAuthGuard, RolesGuard)
@UseInterceptors(AuditLogInterceptor)
export class FirewallController {
  constructor(
    private readonly blacklistService: BlacklistService,
    private readonly whitelistService: WhitelistService,
  ) {}

  @Get('blacklist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @AuditAction('View Blacklist')
  async getBlacklist() {
    return this.blacklistService.list();
  }

  @Post('blacklist')
  @Roles(UserRole.ADMIN)
  @AuditAction('Add to Blacklist')
  async addToBlacklist(@Body() addIpDto: AddIpDto, @Request() req) {
    return this.blacklistService.block(
      addIpDto.ip,
      addIpDto.reason,
      BlockSource.MANUAL,
      req.user.id,
      req.user.username,
    );
  }

  @Delete('blacklist/:ip')
  @Roles(UserRole.ADMIN)
  @AuditAction('Remove from Blacklist')
  async removeFromBlacklist(@Param('ip') ip: string, @Request() req) {
    await this.blacklistService.unblock(ip, req.user.id, req.user.username);
  }

  @Get('whitelist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @AuditAction('View Whitelist')
  async getWhitelist() {
    return this.whitelistService.list();
  }

  @Post('whitelist')
  @Roles(UserRole.ADMIN)
  @AuditAction('Add to Whitelist')
  async addToWhitelist(@Body() addIpDto: AddIpDto, @Request() req) {
    return this.whitelistService.add(
      addIpDto.ip,
      addIpDto.reason,
      req.user.id,
      req.user.username,
    );
  }

  @Delete('whitelist/:ip')
  @Roles(UserRole.ADMIN)
  @AuditAction('Remove from Whitelist')
  async removeFromWhitelist(@Param('ip') ip: string, @Request() req) {
    await this.whitelistService.remove(ip, req.user.id, req.user.username);
  }
}
