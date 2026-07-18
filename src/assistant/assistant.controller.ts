import { Controller, Post, Body, Get, Param, UseGuards, Request } from '@nestjs/common';
import { AssistantService } from './assistant.service';
import { ChatRequestDto } from './dto/chat-request.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from '../users/entities/user.entity';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';

@Controller('assistant')
@UseGuards(JwtAuthGuard, RolesGuard, ThrottlerGuard)
export class AssistantController {
  constructor(private readonly assistantService: AssistantService) {}

  @Post('chat')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  // Limit to 20 requests per hour (3600000ms) for chat
  @Throttle({ default: { limit: 20, ttl: 3600000 } })
  async chat(@Request() req, @Body() chatRequestDto: ChatRequestDto) {
    return this.assistantService.chat(req.user.userId, chatRequestDto);
  }

  @Get('history/:conversationId')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  async getHistory(@Param('conversationId') conversationId: string) {
    return this.assistantService.getHistory(conversationId);
  }

  @Get('quick-actions/:alertId')
  @Roles(UserRole.ANALYST, UserRole.ADMIN)
  @Throttle({ default: { limit: 20, ttl: 3600000 } })
  async getQuickAnalysis(@Request() req, @Param('alertId') alertId: string) {
    return this.assistantService.getQuickAnalysis(req.user.userId, alertId);
  }
}
