import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { WazuhService } from './wazuh.service';
import { AlertsController } from './alerts.controller';
import { AgentsController } from './agents.controller';

@Module({
  imports: [HttpModule, ConfigModule],
  controllers: [AlertsController, AgentsController],
  providers: [WazuhService],
  exports: [WazuhService],
})
export class WazuhModule {}
