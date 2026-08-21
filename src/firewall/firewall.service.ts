import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

@Injectable()
export class FirewallService {
  private readonly logger = new Logger(FirewallService.name);

  /**
   * Validate IP address format with strict IPv4 regex
   * @throws BadRequestException if IP is invalid or protected
   */
  private validateIp(ip: string): void {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;

    if (!ipRegex.test(ip)) {
      throw new BadRequestException(`Invalid IP address format: ${ip}`);
    }

    if (ip === '127.0.0.1' || ip === '0.0.0.0') {
      throw new BadRequestException(`Cannot add protected IP: ${ip}`);
    }
  }

  /**
   * Add IP to an ipset
   * @param setName - Name of the ipset ('blacklist' or 'whitelist')
   * @param ip - IP address to add
   * @throws BadRequestException if IP is invalid
   * @throws InternalServerErrorException if exec command fails
   */
  async addToSet(
    setName: 'blacklist' | 'whitelist',
    ip: string,
  ): Promise<void> {
    this.validateIp(ip);

    try {
      await execFileAsync('sudo', ['ipset', 'add', setName, ip, '-exist']);
      this.logger.log(`Added IP ${ip} to ${setName}`);
    } catch (error: any) {
      this.logger.error(
        `Failed to add IP ${ip} to ${setName}: ${error.message}`,
      );
      throw new InternalServerErrorException(
        `Failed to add IP to ${setName}: ${error.stderr || error.message}`,
      );
    }
  }

  /**
   * Remove IP from an ipset
   * @param setName - Name of the ipset ('blacklist' or 'whitelist')
   * @param ip - IP address to remove
   * @throws BadRequestException if IP is invalid
   * @throws InternalServerErrorException if exec command fails
   */
  async removeFromSet(
    setName: 'blacklist' | 'whitelist',
    ip: string,
  ): Promise<void> {
    this.validateIp(ip);

    try {
      await execFileAsync('sudo', ['ipset', 'del', setName, ip, '-exist']);
      this.logger.log(`Removed IP ${ip} from ${setName}`);
    } catch (error: any) {
      this.logger.error(
        `Failed to remove IP ${ip} from ${setName}: ${error.message}`,
      );
      throw new InternalServerErrorException(
        `Failed to remove IP from ${setName}: ${error.stderr || error.message}`,
      );
    }
  }
}
