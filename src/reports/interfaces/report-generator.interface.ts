export interface ReportGeneratorData {
  userId: number;
  username: string;
  format: 'pdf' | 'excel';
  filters: any;
}

export interface GeneratedReport {
  buffer: Buffer;
  filename: string;
}

export interface ReportGenerator {
  generate(data: ReportGeneratorData): Promise<GeneratedReport>;
  getReportTypeName(): string;
}