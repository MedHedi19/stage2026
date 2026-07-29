import { WebSocketGateway, WebSocketServer, OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect } from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Interval } from '@nestjs/schedule';
import { WazuhService } from '../wazuh/wazuh.service';
import { Logger } from '@nestjs/common';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
})
export class RealtimeGateway implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect {
  private readonly logger = new Logger(RealtimeGateway.name);
  private seenAlertIds = new Set<string>();

  @WebSocketServer()
  server: Server;

  constructor(private readonly wazuhService: WazuhService) {}

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
      const newAlerts = alerts.filter((alert) => !this.seenAlertIds.has(alert.id)).reverse();

      for (const alert of newAlerts) {
        this.seenAlertIds.add(alert.id);
        this.logger.log(`Broadcasting new real-time alert: ${alert.rule?.description || 'Alert'} (${alert.id})`);
        if (this.server) {
          this.server.emit('new-alert', alert);
        }
      }

      // Keep seenSet size bounded
      if (this.seenAlertIds.size > 1000) {
        const recent = Array.from(this.seenAlertIds).slice(-500);
        this.seenAlertIds = new Set(recent);
      }
    } catch (error) {
      this.logger.warn(`Realtime polling skipped: ${error.message}`);
    }
  }
}
