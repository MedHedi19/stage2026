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
  pollNewAlerts() {
    try {
      const alert = this.wazuhService.generateNewAlert();
      this.logger.log(`Broadcasting new real-time alert: ${alert.rule.description} (${alert.id})`);
      if (this.server) {
        this.server.emit('new-alert', alert);
      }
    } catch (error) {
      this.logger.error(`Error broadcasting real-time alert: ${error.message}`);
    }
  }
}
