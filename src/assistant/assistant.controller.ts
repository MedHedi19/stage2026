import { Controller, Post, Body, Get, Param, UseGuards, Request, UseInterceptors } from '@nestjs/common';
import { AssistantService } from './assistant.service';
import { ChatRequestDto } from './dto/chat-request.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from '../users/entities/user.entity';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';
import { AuditAction } from '../audit/audit-action.decorator';

@Controller('assistant')
@UseGuards(JwtAuthGuard, RolesGuard, ThrottlerGuard)
@UseInterceptors(AuditLogInterceptor)
export class AssistantController {
  constructor(private readonly assistantService: AssistantService) {}

  @Post('chat')
  @Roles(UserRole.ANALYST, UserRole.ADMIN, UserRole.VIEWER)
  @AuditAction('Talk with AI')
  // Limit to 20 requests per hour (3600000ms) for chat
  @Throttle({ default: { limit: 20, ttl: 3600000 } })
  async chat(@Request() req, @Body() chatRequestDto: ChatRequestDto) {
    return this.assistantService.chat(req.user.id, req.user.username, req.user.role, chatRequestDto);
  }

  @Get('history/:conversationId')
  @Roles(UserRole.ANALYST, UserRole.ADMIN, UserRole.VIEWER)
  async getHistory(@Param('conversationId') conversationId: string) {
    return this.assistantService.getHistory(conversationId);
  }

  @Get('quick-actions/:alertId')
  @Roles(UserRole.ANALYST, UserRole.ADMIN, UserRole.VIEWER)
  @Throttle({ default: { limit: 20, ttl: 3600000 } })
  async getQuickAnalysis(@Request() req, @Param('alertId') alertId: string) {
    return this.assistantService.getQuickAnalysis(req.user.id, alertId);
  }

  @Get('latest-alert')
  @Roles(UserRole.ANALYST, UserRole.ADMIN, UserRole.VIEWER)
  async getLatestAlert() {
    return this.assistantService.getLatestAlert();
  }

  @Get('daily-summary')
  @Roles(UserRole.ANALYST, UserRole.ADMIN, UserRole.VIEWER)
  async getDailySummary() {
    return this.assistantService.getDailySummary();
  }
}
