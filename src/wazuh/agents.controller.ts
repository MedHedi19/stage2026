import { Controller, Get, UseGuards } from '@nestjs/common';
import { WazuhService } from './wazuh.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from '../users/entities/user.entity';

@Controller('agents')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AgentsController {
  constructor(private readonly wazuhService: WazuhService) {}

  @Get('status')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  async getStatus() {
    return this.wazuhService.fetchAgents();
  }
}
