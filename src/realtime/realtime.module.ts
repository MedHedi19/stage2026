import { Module } from '@nestjs/common';
import { RealtimeGateway } from './realtime.gateway';
import { WazuhModule } from '../wazuh/wazuh.module';
import { FirewallModule } from '../firewall/firewall.module';

@Module({
  imports: [WazuhModule, FirewallModule],
  providers: [RealtimeGateway],
  exports: [RealtimeGateway],
})
export class RealtimeModule {}
