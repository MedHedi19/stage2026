import { Controller, Get, Post, Put, Delete, Body, Param, UseGuards, Request, ParseIntPipe, UseInterceptors, UnauthorizedException } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from './entities/user.entity';
import { AuditAction } from '../audit/audit-action.decorator';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';
import { AuditService } from '../audit/audit.service';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
@UseInterceptors(AuditLogInterceptor)
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly auditService: AuditService,
  ) {}

  @Get('me')
  getProfile(@Request() req) {
    return req.user;
  }

  @Put('me')
  async updateMe(@Request() req, @Body() body: { username?: string; currentPassword?: string; newPassword?: string }) {
    const userId = req.user.id;
    const attrs: any = {};

    if (body.username) {
      attrs.username = body.username;
    }

    if (body.newPassword) {
      if (!body.currentPassword) {
        throw new UnauthorizedException('Current password is required to set a new password');
      }
      // Verify current password
      const existing = await this.usersService.verifyPassword(userId, body.currentPassword);
      if (!existing) {
        throw new UnauthorizedException('Current password is incorrect');
      }
      attrs.password = body.newPassword;
    }

    const result = await this.usersService.update(userId, attrs);
    
    // Log with changed fields
    const changedFieldsStr = result.changedFields.length > 0 ? result.changedFields.join(', ') : 'none';
    await this.auditService.log(
      req.user.id,
      req.user.username,
      'Update Own Profile',
      `User: ${req.user.username} - Changed: ${changedFieldsStr}`,
      req.ip,
    );
    
    return result.user;
  }

  @Get()
  @Roles(UserRole.ADMIN)
  findAll(@Request() req) {
    console.log('[Users] GET /users called');
    console.log('[Users] User from request:', req.user);
    console.log('[Users] User role:', req.user?.role);
    return this.usersService.findAll();
  }

  @Get(':id')
  @Roles(UserRole.ADMIN)
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.findOne(id);
  }

  @Post()
  @Roles(UserRole.ADMIN)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async create(@Request() req, @Body() createUserDto: CreateUserDto) {
    const user = await this.usersService.create(createUserDto.username, createUserDto.password, createUserDto.role);
    
    // Log with username
    await this.auditService.log(
      req.user.id,
      req.user.username,
      'Create User',
      `Created user: ${createUserDto.username} (role: ${createUserDto.role})`,
      req.ip,
    );
    
    return user;
  }

  @Put(':id')
  @Roles(UserRole.ADMIN)
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  async update(@Request() req, @Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    const result = await this.usersService.update(id, updateUserDto);
    
    // Log with username and changed fields
    const changedFieldsStr = result.changedFields.length > 0 ? result.changedFields.join(', ') : 'none';
    await this.auditService.log(
      req.user.id,
      req.user.username,
      'Update User',
      `User: ${result.user.username} - Changed: ${changedFieldsStr}`,
      req.ip,
    );
    
    return result.user;
  }

  @Delete(':id')
  @Roles(UserRole.ADMIN)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async remove(@Request() req, @Param('id', ParseIntPipe) id: number) {
    const user = await this.usersService.remove(id);

    // Log with username
    await this.auditService.log(
      req.user.id,
      req.user.username,
      'Delete User',
      `Deleted user: ${user.username} (role: ${user.role})`,
      req.ip,
    );
  }
}
