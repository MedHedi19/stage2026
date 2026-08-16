import { AssistantService } from './assistant.service';
import { BlockSource } from '../firewall/entities/blacklist-entry.entity';
import { ReportType } from '../reports/report-types.enum';

process.env.GEMINI_API_KEY = process.env.GEMINI_API_KEY || 'test-key';

const generateContentMock = jest.fn();

jest.mock('@google/generative-ai', () => ({
  GoogleGenerativeAI: jest.fn().mockImplementation(() => ({
    getGenerativeModel: jest.fn().mockReturnValue({
      generateContent: generateContentMock,
    }),
  })),
  FunctionCallingMode: { AUTO: 'AUTO' },
  SchemaType: {
    STRING: 'string',
    BOOLEAN: 'boolean',
    ARRAY: 'array',
    OBJECT: 'object',
  },
}));

const threatIntelService = {
  checkIp: jest.fn().mockResolvedValue({
    abuseScore: 75,
    totalReports: 12,
    categories: [14, 18],
    countryCode: 'US',
  }),
};

const threatFeedScheduler = {
  performSync: jest.fn().mockResolvedValue({
    added: 5,
    skipped: 3,
    total: 8,
  }),
};

function mockTextResponse(text: string) {
  return {
    response: {
      text: () => text,
      functionCalls: () => undefined,
      candidates: [{ content: { parts: [{ text }] } }],
    },
  };
}

function mockFunctionThenText(name: string, args: object, finalText: string) {
  generateContentMock
    .mockResolvedValueOnce({
      response: {
        text: () => '',
        functionCalls: () => [{ name, args }],
        candidates: [{ content: { parts: [{ functionCall: { name, args } }] } }],
      },
    })
    .mockResolvedValueOnce(mockTextResponse(finalText));
}

describe('AssistantService tool-driven chat', () => {
  const conversationLogRepo = {
    create: jest.fn((value) => value),
    save: jest.fn(async (value) => value),
    find: jest.fn(async () => []),
  } as any;

  const wazuhService = {
    fetchRecentAlerts: jest.fn(async () => [
      {
        id: 'alert-123',
        rule: { id: '12345', description: 'Port scan', level: 10, groups: ['suricata'] },
        data: { src_ip: '10.0.0.5', dest_ip: '10.0.0.1', dest_port: 443, protocol: 'TCP' },
        timestamp: '2026-08-12T10:00:00Z',
        agent: { name: 'sensor-1' },
      },
    ]),
    getAlertStats: jest.fn(async () => ({
      totalAlerts: 42,
      severityDistribution: { high: 5 },
      attacksByType: {},
      topSourceIps: [],
    })),
  } as any;

  const blacklistService = {
    block: jest.fn(async () => undefined),
    unblock: jest.fn(async () => undefined),
    isBlacklisted: jest.fn(async () => false),
    purgeAll: jest.fn(async () => []),
  } as any;

  const whitelistService = {
    add: jest.fn(async () => undefined),
    remove: jest.fn(async () => undefined),
    isWhitelisted: jest.fn(async () => false),
    purgeAll: jest.fn(async () => []),
  } as any;

  function createService() {
    jest.clearAllMocks();
    generateContentMock.mockReset();
    return new AssistantService(
      conversationLogRepo,
      wazuhService,
      blacklistService,
      whitelistService,
      threatIntelService as any,
      threatFeedScheduler as any,
    );
  }

  it('blocks an IP when the model calls block_ip', async () => {
    const service = createService();
    mockFunctionThenText(
      'block_ip',
      { ips: ['192.168.101.130'] },
      'IP 192.168.101.130 ajoutée à la blacklist.',
    );

    const result = await service.chat(12, 'hedi', {
      message: 'block this address 192.168.101.130',
    });

    expect(blacklistService.block).toHaveBeenCalledWith(
      '192.168.101.130',
      expect.any(String),
      BlockSource.MANUAL,
      12,
      'hedi',
    );
    expect(result.reply).toBe('IP 192.168.101.130 ajoutée à la blacklist.');
    expect(result.mutation).toEqual({ type: 'ip-list-changed', ips: ['192.168.101.130'] });
  });

  it('unblocks an IP when the model calls unblock_ip', async () => {
    const service = createService();
    mockFunctionThenText(
      'unblock_ip',
      { ips: ['192.168.101.130'] },
      'IP 192.168.101.130 retirée de la blacklist.',
    );

    const result = await service.chat(12, 'hedi', {
      message: 'remove 192.168.101.130 from blacklist',
    });

    expect(blacklistService.unblock).toHaveBeenCalledWith('192.168.101.130', 12, 'hedi');
    expect(result.mutation).toEqual({ type: 'ip-list-changed', ips: ['192.168.101.130'] });
  });

  it('adds an IP to the whitelist when the model calls add_to_whitelist', async () => {
    const service = createService();
    mockFunctionThenText(
      'add_to_whitelist',
      { ips: ['192.168.101.130'] },
      'IP ajoutée à la whitelist.',
    );

    await service.chat(12, 'hedi', {
      message: 'add 192.168.101.130 to whitelist',
    });

    expect(whitelistService.add).toHaveBeenCalledWith(
      '192.168.101.130',
      expect.stringContaining('assistant'),
      12,
      'hedi',
    );
  });

  it('analyzes an alert when the model calls analyze_alert', async () => {
    const service = createService();

    generateContentMock
      .mockResolvedValueOnce({
        response: {
          text: () => '',
          functionCalls: () => [{ name: 'analyze_alert', args: { alertId: '12345' } }],
          candidates: [{
            content: { parts: [{ functionCall: { name: 'analyze_alert', args: { alertId: '12345' } } }] },
          }],
        },
      })
      .mockResolvedValueOnce({
        response: {
          text: () =>
            JSON.stringify({
              summary: 'Scan suspect',
              investigationSteps: ['Vérifier les logs'],
              remediationSteps: ['Bloquer la source'],
              isLikelyAttack: true,
              confidence: 'high',
            }),
          functionCalls: () => undefined,
          candidates: [{ content: { parts: [{ text: '{}' }] } }],
        },
      })
      .mockResolvedValueOnce(mockTextResponse('Alerte 12345 : probable attaque, scan de ports détecté.'));

    const result = await service.chat(12, 'hedi', {
      message: 'analyse l alerte 12345, est-ce une attaque ?',
    });

    expect(wazuhService.fetchRecentAlerts).toHaveBeenCalled();
    expect(result.reply).toContain('12345');
  });

  it('generates a report when the model calls generate_report', async () => {
    const service = createService();
    const startDate = '2026-08-05T00:00:00.000Z';
    const endDate = '2026-08-12T23:59:59.999Z';

    mockFunctionThenText(
      'generate_report',
      {
        format: 'pdf',
        reportType: ReportType.EXECUTIVE_SUMMARY,
        startDate,
        endDate,
      },
      'Rapport PDF généré pour les 7 derniers jours.',
    );

    const result = await service.chat(12, 'hedi', {
      message: 'exporte un rapport executive summary en pdf sur 7 jours',
    });

    expect(result.mutation).toEqual({
      type: 'report-request',
      report: {
        format: 'pdf',
        reportType: ReportType.EXECUTIVE_SUMMARY,
        startDate,
        endDate,
      },
    });
  });

  it('reuses last report context for follow-up format change', async () => {
    const service = createService();
    const previousReport = {
      format: 'pdf' as const,
      reportType: ReportType.EXECUTIVE_SUMMARY,
      startDate: '2026-08-05T00:00:00.000Z',
      endDate: '2026-08-12T23:59:59.999Z',
    };

    conversationLogRepo.find.mockResolvedValueOnce([
      {
        userMessage: 'export pdf executive summary 7 days',
        aiReply: 'Rapport PDF généré.',
        metadata: JSON.stringify({ lastReport: previousReport }),
      },
    ]);

    mockFunctionThenText(
      'generate_report',
      {
        format: 'excel',
        reportType: ReportType.EXECUTIVE_SUMMARY,
        startDate: previousReport.startDate,
        endDate: previousReport.endDate,
      },
      'Même rapport généré en Excel.',
    );

    const result = await service.chat(12, 'hedi', {
      message: 'génère le même rapport en excel',
      conversationId: 'conv-1',
    });

    expect(result.mutation?.report?.format).toBe('excel');
    expect(result.mutation?.report?.reportType).toBe(ReportType.EXECUTIVE_SUMMARY);
  });

  it('requires confirmation before purging blacklist via purge_blacklist tool', async () => {
    const service = createService();

    generateContentMock
      .mockResolvedValueOnce({
        response: {
          text: () => '',
          functionCalls: () => [{ name: 'purge_blacklist', args: { confirmed: false } }],
          candidates: [{
            content: { parts: [{ functionCall: { name: 'purge_blacklist', args: { confirmed: false } } }] },
          }],
        },
      })
      .mockResolvedValueOnce(mockTextResponse('Voulez-vous vraiment purger toute la blacklist ?'));

    const result = await service.chat(12, 'hedi', {
      message: 'remove all ips from blacklist',
    });

    expect(blacklistService.purgeAll).not.toHaveBeenCalled();
    expect(result.reply).toContain('purger');
  });

  it('purges blacklist when model calls purge_blacklist with confirmed true', async () => {
    const service = createService();
    blacklistService.purgeAll.mockResolvedValueOnce(['192.168.101.130']);

    mockFunctionThenText(
      'purge_blacklist',
      { confirmed: true },
      '2 IPs retirées de la blacklist.',
    );

    const result = await service.chat(12, 'hedi', {
      message: 'oui, confirme la purge',
    });

    expect(blacklistService.purgeAll).toHaveBeenCalledWith(12, 'hedi');
    expect(result.mutation).toEqual({ type: 'ip-list-changed', ips: ['192.168.101.130'] });
  });
});
