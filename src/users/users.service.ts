import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async create(username: string, passwordPlain: string, role: UserRole): Promise<User> {
    const existing = await this.userRepository.findOne({ where: { username } });
    if (existing) {
      throw new ConflictException('Username already exists');
    }
    const passwordHash = await bcrypt.hash(passwordPlain, 12);
    const user = this.userRepository.create({
      username,
      passwordHash,
      role,
      mfaEnabled: false,
    });
    return this.userRepository.save(user);
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  async findOne(id: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findByUsername(username: string, includeSecrets = false): Promise<User | null> {
    if (includeSecrets) {
      return this.userRepository
        .createQueryBuilder('user')
        .addSelect('user.passwordHash')
        .addSelect('user.mfaSecret')
        .where('user.username = :username', { username })
        .getOne();
    }
    return this.userRepository.findOne({ where: { username } });
  }

  async update(id: number, attrs: Partial<User> & { password?: string }): Promise<User> {
    const user = await this.findOne(id);
    
    if (attrs.username && attrs.username !== user.username) {
      const existing = await this.userRepository.findOne({ where: { username: attrs.username } });
      if (existing) {
        throw new ConflictException('Username already exists');
      }
      user.username = attrs.username;
    }

    if (attrs.password) {
      user.passwordHash = await bcrypt.hash(attrs.password, 12);
    }

    if (attrs.role) {
      user.role = attrs.role;
    }

    if (attrs.mfaEnabled !== undefined) {
      user.mfaEnabled = attrs.mfaEnabled;
      if (!attrs.mfaEnabled) {
        user.mfaSecret = null;
      }
    }

    if (attrs.mfaSecret !== undefined) {
      user.mfaSecret = attrs.mfaSecret;
    }

    return this.userRepository.save(user);
  }

  async remove(id: number): Promise<void> {
    const user = await this.findOne(id);
    await this.userRepository.remove(user);
  }
}
