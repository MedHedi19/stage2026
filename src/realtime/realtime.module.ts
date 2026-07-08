import { Module } from '@nestjs/common';
import { RealtimeGateway } from './realtime.gateway';
import { WazuhModule } from '../wazuh/wazuh.module';

@Module({
  imports: [WazuhModule],
  providers: [RealtimeGateway],
  exports: [RealtimeGateway],
})
export class RealtimeModule {}
