import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { of, throwError } from 'rxjs';
import { ThreatIntelService } from './threat-intel.service';

describe('ThreatIntelService', () => {
  let service: ThreatIntelService;
  let httpService: HttpService;
  let configService: ConfigService;

  const createService = async (apiKey: string = '') => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ThreatIntelService,
        {
          provide: HttpService,
          useValue: {
            get: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue(apiKey),
          },
        },
      ],
    }).compile();

    service = module.get<ThreatIntelService>(ThreatIntelService);
    httpService = module.get<HttpService>(HttpService);
    configService = module.get<ConfigService>(ConfigService);
    return service;
  };

  beforeEach(async () => {
    jest.clearAllMocks();
  });

  describe('checkIp', () => {
    it('should return null when API key is not configured', async () => {
      service = await createService('');

      const result = await service.checkIp('192.168.1.1');

      expect(result).toBeNull();
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('should return threat intel data on successful API call', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: {
            abuseConfidenceScore: 85,
            totalReports: 12,
            countryCode: 'US',
            reports: [
              { categories: [14, 18] },
              { categories: [14, 22] },
            ],
          },
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.checkIp('192.168.1.1');

      expect(result).toEqual({
        abuseScore: 85,
        totalReports: 12,
        categories: [14, 18, 22],
        countryCode: 'US',
      });
      expect(httpService.get).toHaveBeenCalledWith(
        'https://api.abuseipdb.com/api/v2/check',
        {
          headers: {
            Key: 'test-api-key',
            Accept: 'application/json',
          },
          params: {
            ipAddress: '192.168.1.1',
            maxAgeInDays: 90,
          },
          timeout: 10000,
        }
      );
    });

    it('should handle empty reports array', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: {
            abuseConfidenceScore: 50,
            totalReports: 0,
            countryCode: 'FR',
            reports: [],
          },
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.checkIp('10.0.0.1');

      expect(result).toEqual({
        abuseScore: 50,
        totalReports: 0,
        categories: [],
        countryCode: 'FR',
      });
    });

    it('should handle missing reports field', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: {
            abuseConfidenceScore: 75,
            totalReports: 5,
            countryCode: 'DE',
          },
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.checkIp('172.16.0.1');

      expect(result).toEqual({
        abuseScore: 75,
        totalReports: 5,
        categories: [],
        countryCode: 'DE',
      });
    });

    it('should return null on API error', async () => {
      service = await createService('test-api-key');
      (httpService.get as jest.Mock).mockReturnValue(
        throwError(new Error('Rate limit exceeded'))
      );

      const result = await service.checkIp('192.168.1.1');

      expect(result).toBeNull();
    });

    it('should return null on network error', async () => {
      service = await createService('test-api-key');
      (httpService.get as jest.Mock).mockReturnValue(
        throwError(new Error('ETIMEDOUT'))
      );

      const result = await service.checkIp('192.168.1.1');

      expect(result).toBeNull();
    });

    it('should return null when response data is empty', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: null,
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.checkIp('192.168.1.1');

      expect(result).toBeNull();
    });

    it('should dedupe categories from multiple reports', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: {
            abuseConfidenceScore: 95,
            totalReports: 3,
            countryCode: 'RU',
            reports: [
              { categories: [14, 14, 18] },
              { categories: [18, 22] },
              { categories: [14, 22, 22] },
            ],
          },
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.checkIp('192.168.1.1');

      expect(result).toEqual({
        abuseScore: 95,
        totalReports: 3,
        categories: [14, 18, 22],
        countryCode: 'RU',
      });
    });
  });

  describe('getBlocklist', () => {
    it('should return empty array when API key is not configured', async () => {
      service = await createService('');

      const result = await service.getBlocklist();

      expect(result).toEqual([]);
      expect(httpService.get).not.toHaveBeenCalled();
    });

    it('should return array of IPs on successful API call', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: [
            { ipAddress: '192.168.1.100' },
            { ipAddress: '10.0.0.50' },
            { ipAddress: '172.16.0.1' },
          ],
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.getBlocklist(90);

      expect(result).toEqual(['192.168.1.100', '10.0.0.50', '172.16.0.1']);
      expect(httpService.get).toHaveBeenCalledWith(
        'https://api.abuseipdb.com/api/v2/blacklist',
        {
          headers: {
            Key: 'test-api-key',
            Accept: 'application/json',
          },
          params: {
            confidenceMinimum: 90,
            limit: 1000,
          },
          timeout: 10000,
        }
      );
    });

    it('should use default confidence minimum of 90', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: [{ ipAddress: '192.168.1.100' }],
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      await service.getBlocklist();

      expect(httpService.get).toHaveBeenCalledWith(
        'https://api.abuseipdb.com/api/v2/blacklist',
        expect.objectContaining({
          params: expect.objectContaining({
            confidenceMinimum: 90,
          }),
        })
      );
    });

    it('should return empty array on API error', async () => {
      service = await createService('test-api-key');
      (httpService.get as jest.Mock).mockReturnValue(
        throwError(new Error('Rate limit exceeded'))
      );

      const result = await service.getBlocklist();

      expect(result).toEqual([]);
    });

    it('should return empty array when response data is invalid', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: null,
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.getBlocklist();

      expect(result).toEqual([]);
    });

    it('should return empty array when response data is not an array', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: 'invalid',
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.getBlocklist();

      expect(result).toEqual([]);
    });

    it('should filter out null/undefined IP addresses', async () => {
      service = await createService('test-api-key');
      const mockAxiosResponse = {
        data: {
          data: [
            { ipAddress: '192.168.1.100' },
            { ipAddress: null },
            { ipAddress: '10.0.0.50' },
            { ipAddress: undefined },
          ],
        },
      };
      (httpService.get as jest.Mock).mockReturnValue(of(mockAxiosResponse));

      const result = await service.getBlocklist();

      expect(result).toEqual(['192.168.1.100', '10.0.0.50']);
    });
  });
});
