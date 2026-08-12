import { Controller, Get, Post, Delete, Body, Param, UseGuards, Request, UseInterceptors, Query } from '@nestjs/common';
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
import { FirewallHistoryService } from './firewall-history.service';
import { FirewallListType } from './entities/firewall-history.entity';

@Controller('ips')
@UseGuards(JwtAuthGuard, RolesGuard)
@UseInterceptors(AuditLogInterceptor)
export class FirewallController {
  constructor(
    private readonly blacklistService: BlacklistService,
    private readonly whitelistService: WhitelistService,
    private readonly firewallHistoryService: FirewallHistoryService,
  ) {}

  @Get('blacklist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @AuditAction('View Blacklist')
  async getBlacklist() {
    return this.blacklistService.list();
  }

  @Post('blacklist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
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
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async removeFromBlacklist(@Param('ip') ip: string, @Request() req) {
    await this.blacklistService.unblock(ip, req.user.id, req.user.username);
  }

  @Get('whitelist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @AuditAction('View Whitelist')
  async getWhitelist() {
    return this.whitelistService.list();
  }

  @Post('whitelist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async addToWhitelist(@Body() addIpDto: AddIpDto, @Request() req) {
    return this.whitelistService.add(
      addIpDto.ip,
      addIpDto.reason,
      req.user.id,
      req.user.username,
    );
  }

  @Delete('whitelist/:ip')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async removeFromWhitelist(@Param('ip') ip: string, @Request() req) {
    await this.whitelistService.remove(ip, req.user.id, req.user.username);
  }

  @Get('history')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @AuditAction('View Firewall History')
  async getFirewallHistory(
    @Query('listType') listType?: string,
    @Query('limit') limit?: string,
  ) {
    let parsedListType: FirewallListType | undefined;
    if (listType === 'blacklist') parsedListType = FirewallListType.BLACKLIST;
    else if (listType === 'whitelist') parsedListType = FirewallListType.WHITELIST;

    const parsedLimit = limit ? parseInt(limit, 10) : undefined;
    return this.firewallHistoryService.getHistory(parsedListType, parsedLimit);
  }
}
