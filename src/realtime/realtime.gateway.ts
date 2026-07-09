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
  private lastBroadcastAlertId: string | null = null;

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

  @Interval(5000)
  async pollNewAlerts() {
    try {
      const alerts = await this.wazuhService.fetchRecentAlerts({ limit: 1 });
      const latestAlert = alerts[0];
      if (latestAlert && latestAlert.id !== this.lastBroadcastAlertId) {
        this.lastBroadcastAlertId = latestAlert.id;
        this.logger.log(`Broadcasting new real-time alert: ${latestAlert.rule.description} (${latestAlert.id})`);
        if (this.server) {
          this.server.emit('new-alert', latestAlert);
        }
      }
    } catch (error) {
      this.logger.warn(`Realtime polling skipped: ${error.message}`);
    }
  }
}
