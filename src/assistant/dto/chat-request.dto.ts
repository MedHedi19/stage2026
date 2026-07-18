import { IsString, IsOptional } from 'class-validator';

export class ChatRequestDto {
  @IsString()
  message: string;

  @IsString()
  @IsOptional()
  alertId?: string;

  @IsString()
  @IsOptional()
  conversationId?: string;
}
