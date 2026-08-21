import { Controller, Get, Post, Delete, Body, Param, UseGuards, Request, UseInterceptors, Query } from '@nestjs/common';
import { BlacklistService } from './blacklist.service';
import { WhitelistService } from './whitelist.service';
import { ThreatIntelService } from './threat-intel.service';
import { ThreatFeedScheduler } from './threat-feed.scheduler';
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
    private readonly threatIntelService: ThreatIntelService,
    private readonly threatFeedScheduler: ThreatFeedScheduler,
  ) {}

  @Get('blacklist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @AuditAction('View Blacklist')
  async getBlacklist(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('search') search?: string,
  ) {
    const parsedPage = Math.max(1, page ? parseInt(page, 10) || 1 : 1);
    const parsedLimit = Math.max(1, Math.min(1000, limit ? parseInt(limit, 10) || 30 : 30));
    const [data, total] = await Promise.all([
      this.blacklistService.list(parsedPage, parsedLimit, search),
      this.blacklistService.count(search),
    ]);
    return { data, total, page: parsedPage, limit: parsedLimit };
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

  @Get('check-reputation/:ip')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async checkReputation(@Param('ip') ip: string) {
    return this.threatIntelService.checkIp(ip);
  }

  @Post('sync-threat-feed')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @AuditAction('Sync Threat Feed (AbuseIPDB)')
  async syncThreatFeed(
    @Query('limit') queryLimit?: string,
    @Body('limit') bodyLimit?: number,
  ) {
    const limit = bodyLimit || (queryLimit ? parseInt(queryLimit, 10) : 20);
    return this.threatFeedScheduler.performSync(limit);
  }

  @Get('country-stats')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @AuditAction('View Country Statistics')
  async getCountryStats() {
    return this.blacklistService.getCountryStats();
  }

  @Post('backfill-country-codes')
  @Roles(UserRole.ADMIN)
  @AuditAction('Backfill Country Codes')
  async backfillCountryCodes() {
    const updated = await this.blacklistService.backfillCountryCodes();
    return { updated, message: `Updated ${updated} entries with country codes` };
  }

  @Get('whitelist')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @AuditAction('View Whitelist')
  async getWhitelist(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('search') search?: string,
  ) {
    const parsedPage = Math.max(1, page ? parseInt(page, 10) || 1 : 1);
    const parsedLimit = Math.max(1, Math.min(1000, limit ? parseInt(limit, 10) || 30 : 30));
    const [data, total] = await Promise.all([
      this.whitelistService.list(parsedPage, parsedLimit, search),
      this.whitelistService.count(search),
    ]);
    return { data, total, page: parsedPage, limit: parsedLimit };
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
