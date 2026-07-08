import { Injectable, OnApplicationBootstrap, Logger } from '@nestjs/common';
import { UsersService } from './users/users.service';
import { UserRole } from './users/entities/user.entity';

@Injectable()
export class AppService implements OnApplicationBootstrap {
  private readonly logger = new Logger(AppService.name);

  constructor(private readonly usersService: UsersService) {}

  getHello(): string {
    return 'IDS/IPS Cybersecurity Dashboard API is running.';
  }

  async onApplicationBootstrap() {
    this.logger.log('Checking database users...');
    try {
      const users = await this.usersService.findAll();
      if (users.length === 0) {
        this.logger.log('No users found in database. Seeding default accounts...');
        
        await this.usersService.create('admin', 'admin123', UserRole.ADMIN);
        this.logger.log('Seeded User: admin / admin123 (admin)');

        await this.usersService.create('analyst', 'analyst123', UserRole.ANALYST);
        this.logger.log('Seeded User: analyst / analyst123 (analyst)');

        await this.usersService.create('viewer', 'viewer123', UserRole.VIEWER);
        this.logger.log('Seeded User: viewer / viewer123 (viewer)');
        
        this.logger.log('Database seeding completed successfully.');
      } else {
        this.logger.log(`Found ${users.length} users in database. Skipping seeding.`);
      }
    } catch (error) {
      this.logger.error(`Error checking/seeding database: ${error.message}`);
    }
  }
}
