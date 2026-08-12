import { IsString, IsOptional, IsIn, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { ReportType } from '../../reports/report-types.enum';

class LastReportDto {
  @IsIn(['pdf', 'excel'])
  format: 'pdf' | 'excel';

  @IsString()
  reportType: ReportType;

  @IsString()
  startDate: string;

  @IsString()
  endDate: string;
}

export class ChatRequestDto {
  @IsString()
  message: string;

  @IsString()
  @IsOptional()
  alertId?: string;

  @IsString()
  @IsOptional()
  conversationId?: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => LastReportDto)
  lastReport?: LastReportDto;
}
