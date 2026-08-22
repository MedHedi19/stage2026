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

  @Interval(3000)
  async pollNewAlerts() {
    try {
      const alerts = await this.wazuhService.fetchRecentAlerts({ limit: 10 });
      if (!alerts || alerts.length === 0) return;

      // On very first run, populate seen set without broadcasting old historical alerts
      if (this.seenAlertIds.size === 0) {
        alerts.forEach((alert) => this.seenAlertIds.add(alert.id));
        return;
      }

      // Find new alerts not yet broadcasted (alerts are sorted newest first)
      const newAlerts = alerts
        .filter((alert) => !this.seenAlertIds.has(alert.id))
        .reverse();

      for (const alert of newAlerts) {
        this.seenAlertIds.add(alert.id);
        this.logger.log(
          `Broadcasting new real-time alert: ${alert.rule?.description || 'Alert'} (${alert.id})`,
        );
        if (this.server) {
          this.server.emit('new-alert', alert);
        }

        // Auto-block logic
        const srcIp = alert.data?.src_ip;
        if (srcIp) {
          try {
            // Extract SID from correct path: alert.data.alert.signature_id (string)
            const sid = Number(alert.data?.alert?.signature_id);
            const isInAutoBlockList = AUTO_BLOCK_SIDS.includes(sid);

            // Check whitelist first
            const isWhitelisted =
              await this.whitelistService.isWhitelisted(srcIp);

            // Debug logging
            console.log(
              '[Auto-Block] srcIp:',
              srcIp,
              'sid:',
              sid,
              'inAutoBlockList:',
              isInAutoBlockList,
              'isWhitelisted:',
              isWhitelisted,
            );

            if (isWhitelisted) {
              this.logger.log(
                `IP ${srcIp} is whitelisted, skipping auto-block`,
              );
              continue;
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
                // Threat intel is enrichment only - don't fail the block if it errors
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
            // Continue - don't break alert broadcast
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
    }
  }
}
