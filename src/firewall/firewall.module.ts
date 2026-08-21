import { Module, OnModuleInit, Logger } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { BlacklistEntry } from './entities/blacklist-entry.entity';
import { WhitelistEntry } from './entities/whitelist-entry.entity';
import { FirewallHistory } from './entities/firewall-history.entity';
import { FirewallService } from './firewall.service';
import { BlacklistService } from './blacklist.service';
import { WhitelistService } from './whitelist.service';
import { FirewallHistoryService } from './firewall-history.service';
import { ThreatIntelService } from './threat-intel.service';
import { ThreatFeedScheduler } from './threat-feed.scheduler';
import { FirewallController } from './firewall.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([BlacklistEntry, WhitelistEntry, FirewallHistory]),
    HttpModule,
    ConfigModule,
  ],
  controllers: [FirewallController],
  providers: [
    FirewallService,
    BlacklistService,
    WhitelistService,
    FirewallHistoryService,
    ThreatIntelService,
    ThreatFeedScheduler,
  ],
  exports: [
    TypeOrmModule,
    FirewallService,
    BlacklistService,
    WhitelistService,
    FirewallHistoryService,
    ThreatIntelService,
    ThreatFeedScheduler,
  ],
})
export class FirewallModule implements OnModuleInit {
  private readonly logger = new Logger(FirewallModule.name);

  constructor(
    @InjectRepository(BlacklistEntry)
    private blacklistRepository: Repository<BlacklistEntry>,
    @InjectRepository(WhitelistEntry)
    private whitelistRepository: Repository<WhitelistEntry>,
    private readonly firewallService: FirewallService,
  ) {}

  async onModuleInit() {
    this.logger.log('Starting firewall ipset synchronization...');

    // Restore blacklist from database
    const blacklistEntries = await this.blacklistRepository.find({
      where: { active: true },
    });

    let blacklistRestored = 0;
    for (const entry of blacklistEntries) {
      try {
        await this.firewallService.addToSet('blacklist', entry.ip);
        blacklistRestored++;
      } catch (error: any) {
        this.logger.warn(
          `Failed to restore blacklist IP ${entry.ip}: ${error.message}`,
        );
      }
    }

    this.logger.log(
      `Restored ${blacklistRestored}/${blacklistEntries.length} blacklist entries to ipset`,
    );

    // Restore whitelist from database
    const whitelistEntries = await this.whitelistRepository.find();

    let whitelistRestored = 0;
    for (const entry of whitelistEntries) {
      try {
        await this.firewallService.addToSet('whitelist', entry.ip);
        whitelistRestored++;
      } catch (error: any) {
        this.logger.warn(
          `Failed to restore whitelist IP ${entry.ip}: ${error.message}`,
        );
      }
    }

    this.logger.log(
      `Restored ${whitelistRestored}/${whitelistEntries.length} whitelist entries to ipset`,
    );
    this.logger.log('Firewall ipset synchronization completed');
  }
}
