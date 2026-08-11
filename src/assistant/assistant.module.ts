import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AssistantController } from './assistant.controller';
import { AssistantService } from './assistant.service';
import { ConversationLog } from './entities/conversation-log.entity';
import { WazuhModule } from '../wazuh/wazuh.module';
import { FirewallModule } from '../firewall/firewall.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([ConversationLog]),
    WazuhModule,
    FirewallModule,
  ],
  controllers: [AssistantController],
  providers: [AssistantService],
})
export class AssistantModule {}
