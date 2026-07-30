import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { FirewallService } from './firewall.service';
import { execFile } from 'child_process';
import { promisify } from 'util';

jest.mock('child_process');
const execFileMock = execFile as jest.MockedFunction<typeof execFile>;
const execFileAsync = promisify(execFileMock);

describe('FirewallService', () => {
  let service: FirewallService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [FirewallService],
    }).compile();

    service = module.get<FirewallService>(FirewallService);
    jest.clearAllMocks();
  });

  describe('validateIp', () => {
    it('should accept valid IPv4 addresses', () => {
      const validIps = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8'];
      validIps.forEach(ip => {
        expect(() => (service as any).validateIp(ip)).not.toThrow();
      });
    });

    it('should reject invalid IP formats', () => {
      const invalidIps = [
        '256.1.1.1',
        '192.168.1',
        '192.168.1.1.1',
        'invalid',
        '',
        '192.168.1.999',
      ];
      invalidIps.forEach(ip => {
        expect(() => (service as any).validateIp(ip)).toThrow(BadRequestException);
      });
    });

    it('should reject protected IPs', () => {
      const protectedIps = ['127.0.0.1', '0.0.0.0'];
      protectedIps.forEach(ip => {
        expect(() => (service as any).validateIp(ip)).toThrow(BadRequestException);
      });
    });
  });

  describe('addToSet', () => {
    it('should call execFile with correct arguments for valid IP', async () => {
      (execFileMock as any).mockResolvedValue({ stdout: '', stderr: '' });

      await service.addToSet('blacklist', '192.168.1.100');

      expect(execFileMock).toHaveBeenCalledWith(
        'sudo',
        ['ipset', 'add', 'blacklist', '192.168.1.100', '-exist']
      );
    });

    it('should call execFile with correct arguments for whitelist', async () => {
      (execFileMock as any).mockResolvedValue({ stdout: '', stderr: '' });

      await service.addToSet('whitelist', '10.0.0.50');

      expect(execFileMock).toHaveBeenCalledWith(
        'sudo',
        ['ipset', 'add', 'whitelist', '10.0.0.50', '-exist']
      );
    });

    it('should throw BadRequestException for invalid IP before calling execFile', async () => {
      await expect(service.addToSet('blacklist', 'invalid-ip')).rejects.toThrow(
        BadRequestException
      );
      expect(execFileMock).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException for protected IP before calling execFile', async () => {
      await expect(service.addToSet('blacklist', '127.0.0.1')).rejects.toThrow(
        BadRequestException
      );
      expect(execFileMock).not.toHaveBeenCalled();
    });

    it('should throw InternalServerErrorException on exec error', async () => {
      const error = new Error('Permission denied');
      (error as any).stderr = 'sudo: no tty present';
      (execFileMock as any).mockRejectedValue(error);

      await expect(service.addToSet('blacklist', '192.168.1.100')).rejects.toThrow(
        InternalServerErrorException
      );
    });

    it('should include stderr in error message when available', async () => {
      const error = new Error('Command failed');
      (error as any).stderr = 'ipset: cannot create set';
      (execFileMock as any).mockRejectedValue(error);

      await expect(service.addToSet('blacklist', '192.168.1.100')).rejects.toThrow(
        InternalServerErrorException
      );
    });
  });

  describe('removeFromSet', () => {
    it('should call execFile with correct arguments for valid IP', async () => {
      (execFileMock as any).mockResolvedValue({ stdout: '', stderr: '' });

      await service.removeFromSet('blacklist', '192.168.1.100');

      expect(execFileMock).toHaveBeenCalledWith(
        'sudo',
        ['ipset', 'del', 'blacklist', '192.168.1.100']
      );
    });

    it('should throw BadRequestException for invalid IP before calling execFile', async () => {
      await expect(service.removeFromSet('whitelist', 'invalid')).rejects.toThrow(
        BadRequestException
      );
      expect(execFileMock).not.toHaveBeenCalled();
    });

    it('should throw InternalServerErrorException on exec error', async () => {
      const error = new Error('Set not found');
      (error as any).stderr = 'ipset: Set blacklist does not exist';
      (execFileMock as any).mockRejectedValue(error);

      await expect(service.removeFromSet('blacklist', '192.168.1.100')).rejects.toThrow(
        InternalServerErrorException
      );
    });
  });
});
