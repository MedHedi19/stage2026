import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Interval } from '@nestjs/schedule';
import { WazuhService } from '../wazuh/wazuh.service';
import { Logger } from '@nestjs/common';
import { WhitelistService } from '../firewall/whitelist.service';
import { BlacklistService } from '../firewall/blacklist.service';
import { ThreatIntelService } from '../firewall/threat-intel.service';
import { BlockSource } from '../firewall/entities/blacklist-entry.entity';
import { AUTO_BLOCK_SIDS } from '../firewall/auto-block.config';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
})
export class RealtimeGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  private readonly logger = new Logger(RealtimeGateway.name);
  private seenAlertIds = new Set<string>();
  private isPolling = false;
  private lastPollTime: string = new Date(Date.now() - 30000).toISOString();

  @WebSocketServer()
  server: Server;

  constructor(
    private readonly wazuhService: WazuhService,
    private readonly whitelistService: WhitelistService,
    private readonly blacklistService: BlacklistService,
    private readonly threatIntelService: ThreatIntelService,
  ) {}

  afterInit(server: Server) {
    this.logger.log('WebSocket Gateway Initialized');
  }

  handleConnection(client: Socket) {
    this.logger.log(`Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  @Interval(1000)
  async pollNewAlerts() {
    if (this.isPolling) return;
    this.isPolling = true;

    try {
      // Query alerts starting from lastPollTime to prevent high-volume logs from drowning out security alerts
      const alerts = await this.wazuhService.fetchRecentAlerts({
        startDate: this.lastPollTime,
        limit: 200,
      });

      if (alerts && alerts.length > 0) {
        // Find new alerts not yet broadcasted
        const newAlerts = alerts
          .filter((alert) => !this.seenAlertIds.has(alert.id))
          .reverse();

        for (const alert of newAlerts) {
          this.seenAlertIds.add(alert.id);
          this.logger.log(
            `Broadcasting new real-time alert: ${alert.rule?.description || 'Alert'} (${alert.id})`,
          );

          // 1. Instant WebSocket emission to connected dashboards
          if (this.server) {
            this.server.emit('new-alert', alert);
          }

          // 2. Non-blocking Auto-block & Threat Intel processing in background
          this.processAutoBlock(alert).catch((err) =>
            this.logger.error(`Background auto-block error: ${err.message}`),
          );
        }

        // Advance lastPollTime safely (1s safety margin before newest timestamp)
        const newestTimestamp = alerts[0]?.timestamp;
        if (newestTimestamp) {
          const newestDate = new Date(newestTimestamp);
          if (!isNaN(newestDate.getTime())) {
            this.lastPollTime = new Date(
              newestDate.getTime() - 1000,
            ).toISOString();
          }
        }
      }

      // Keep seenSet size bounded
      if (this.seenAlertIds.size > 1000) {
        const recent = Array.from(this.seenAlertIds).slice(-500);
        this.seenAlertIds = new Set(recent);
      }
    } catch (error: any) {
      this.logger.warn(`Realtime polling skipped: ${error.message}`);
    } finally {
      this.isPolling = false;
    }
  }

  private async processAutoBlock(alert: any) {
    const srcIp = alert.data?.src_ip;
    if (!srcIp) return;

    try {
      // Extract SID from correct path: alert.data.alert.signature_id (string)
      const sid = Number(alert.data?.alert?.signature_id);
      const isInAutoBlockList = AUTO_BLOCK_SIDS.includes(sid);

      // Check whitelist first
      const isWhitelisted =
        await this.whitelistService.isWhitelisted(srcIp);

      if (isWhitelisted) {
        this.logger.log(
          `IP ${srcIp} is whitelisted, skipping auto-block`,
        );
        return;
      }

      // Check if IP is already blacklisted
      const isBlacklisted = await this.blacklistService.isBlacklisted(srcIp);
      if (isBlacklisted) {
        this.logger.log(
          `IP ${srcIp} is already blacklisted, skipping auto-block`,
        );
        return;
      }

      // Check if SID triggers auto-block
      if (isInAutoBlockList) {
        const description = alert.rule?.description || 'Unknown threat';

        // Enrich with threat intelligence (optional - don't fail if API is down)
        let blockReason = `Auto-blocked: ${description}`;
        let threatData:
          | {
              abuseScore?: number;
              abuseCategories?: string;
              countryCode?: string;
            }
          | undefined;

        try {
          const threatInfo = await this.threatIntelService.checkIp(srcIp);
          if (threatInfo && threatInfo.sources?.abuseipdb) {
            const abuseData = threatInfo.sources.abuseipdb;
            blockReason += ` (AbuseIPDB score: ${abuseData.score}/100, ${abuseData.totalReports} reports)`;
            threatData = {
              abuseScore: abuseData.score,
              abuseCategories: abuseData.categories.join(','),
              countryCode: threatInfo.countryCode,
            };
          }
        } catch (error: any) {
          this.logger.warn(
            `Threat intel check failed for ${srcIp}: ${error.message}`,
          );
        }

        await this.blacklistService.block(
          srcIp,
          blockReason,
          BlockSource.AUTO,
          null,
          null,
          threatData,
        );
        this.logger.log(`Auto-blocked IP ${srcIp} for SID ${sid}`);
      }
    } catch (error: any) {
      this.logger.error(
        `Auto-block failed for IP ${srcIp}: ${error.message}`,
      );
    }
  }
}
