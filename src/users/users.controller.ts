import { Controller, Get, Post, Put, Delete, Body, Param, UseGuards, Request, ParseIntPipe, UseInterceptors, UnauthorizedException } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../roles/roles.guard';
import { Roles } from '../roles/roles.decorator';
import { UserRole } from './entities/user.entity';
import { AuditAction } from '../audit/audit-action.decorator';
import { AuditLogInterceptor } from '../audit/audit-log.interceptor';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
@UseInterceptors(AuditLogInterceptor)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('me')
  getProfile(@Request() req) {
    return req.user;
  }

  @Put('me')
  @AuditAction('Update Own Profile')
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

    return this.usersService.update(userId, attrs);
  }

  @Get()
  @Roles(UserRole.ADMIN)
  findAll() {
    return this.usersService.findAll();
  }

  @Get(':id')
  @Roles(UserRole.ADMIN)
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.findOne(id);
  }

  @Post()
  @Roles(UserRole.ADMIN)
  @AuditAction('Create User')
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto.username, createUserDto.password, createUserDto.role);
  }

  @Put(':id')
  @Roles(UserRole.ADMIN)
  @AuditAction('Update User')
  update(@Param('id', ParseIntPipe) id: number, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @Delete(':id')
  @Roles(UserRole.ADMIN)
  @AuditAction('Delete User')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.remove(id);
  }
}
