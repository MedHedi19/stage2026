import { AssistantService } from './assistant.service';
import { BlockSource } from '../firewall/entities/blacklist-entry.entity';

process.env.GEMINI_API_KEY = process.env.GEMINI_API_KEY || 'test-key';

describe('AssistantService firewall commands', () => {
  const conversationLogRepo = {
    create: jest.fn((value) => value),
    save: jest.fn(async (value) => value),
    find: jest.fn(async () => []),
  } as any;

  const wazuhService = {} as any;
  const blacklistService = {
    block: jest.fn(async () => undefined),
    unblock: jest.fn(async () => undefined),
    isBlacklisted: jest.fn(async () => false),
  } as any;
  const whitelistService = {
    add: jest.fn(async () => undefined),
    remove: jest.fn(async () => undefined),
    isWhitelisted: jest.fn(async () => false),
  } as any;

  function createService() {
    jest.clearAllMocks();
    return new AssistantService(
      conversationLogRepo,
      wazuhService,
      blacklistService,
      whitelistService,
    );
  }

  it('blocks an IP when asked to block it', async () => {
    const service = createService();

    const result = await service.chat(12, 'hedi', {
      message: 'block this address 192.168.101.130',
    });

    expect(blacklistService.block).toHaveBeenCalledWith(
      '192.168.101.130',
      expect.stringContaining('block this address 192.168.101.130'),
      BlockSource.MANUAL,
      12,
      'hedi',
    );
    expect(result.reply).toBe('IP 192.168.101.130 ajoutée à la blacklist.');
    expect(result.mutation).toEqual({ type: 'ip-list-changed', ips: ['192.168.101.130'] });
  });

  it('removes an IP from the blacklist when asked to remove it', async () => {
    blacklistService.isBlacklisted.mockResolvedValue(true);
    const service = createService();

    const result = await service.chat(12, 'hedi', {
      message: 'remove 192.168.101.130',
    });

    expect(blacklistService.unblock).toHaveBeenCalledWith(
      '192.168.101.130',
      12,
      'hedi',
    );
    expect(result.reply).toBe('IP 192.168.101.130 retirée de la blacklist.');
  });

  it('adds an IP to the whitelist when asked', async () => {
    const service = createService();

    const result = await service.chat(12, 'hedi', {
      message: 'add 192.168.101.130 to whitelist',
    });

    expect(whitelistService.add).toHaveBeenCalledWith(
      '192.168.101.130',
      expect.stringContaining('Ajoutée via assistant'),
      12,
      'hedi',
    );
    expect(result.reply).toBe('IP 192.168.101.130 ajoutée à la whitelist.');
  });

  it('removes an IP from the whitelist when asked', async () => {
    const service = createService();

    const result = await service.chat(12, 'hedi', {
      message: 'remove 192.168.101.130 from whitelist',
    });

    expect(whitelistService.remove).toHaveBeenCalledWith(
      '192.168.101.130',
      12,
      'hedi',
    );
    expect(result.reply).toBe('IP 192.168.101.130 retirée de la whitelist.');
  });

  it('handles multiple IPs in a single blacklist removal command', async () => {
    blacklistService.isBlacklisted.mockResolvedValue(true);
    const service = createService();

    const result = await service.chat(12, 'hedi', {
      message: 'remove 192.168.101.190 192.168.101.153 from the black list',
    });

    expect(blacklistService.unblock).toHaveBeenNthCalledWith(1, '192.168.101.190', 12, 'hedi');
    expect(blacklistService.unblock).toHaveBeenNthCalledWith(2, '192.168.101.153', 12, 'hedi');
    expect(result.reply).toContain('192.168.101.190, 192.168.101.153');
    expect(result.mutation).toEqual({ type: 'ip-list-changed', ips: ['192.168.101.190', '192.168.101.153'] });
  });

  it('asks for IPs when a firewall command has no address', async () => {
    const service = createService();

    const result = await service.chat(12, 'hedi', {
      message: 'remove all the ips from the black list',
    });

    expect(result.reply).toContain('Donnez-moi une ou plusieurs adresses IP');
  });
});
