import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getApiDocumentation() {
    return {
      name: 'IDS/IPS Cybersecurity Dashboard API',
      version: '1.0.0',
      description: 'Security monitoring dashboard API for Wazuh IDS/IPS integration with user management, reporting, and audit logging',
      baseUrl: '/api',
      endpoints: [
        {
          category: 'Authentication',
          routes: [
            {
              method: 'POST',
              path: '/auth/login',
              description: 'User login with username and password',
              auth: false,
              body: { username: 'string', password: 'string' },
              response: { accessToken: 'string', requiresMfa: 'boolean', tempToken: 'string (if MFA required)' }
            },
            {
              method: 'POST',
              path: '/auth/signup',
              description: 'Create new user account',
              auth: false,
              body: { username: 'string', password: 'string' },
              response: { id: 'number', username: 'string', role: 'string' }
            },
            {
              method: 'POST',
              path: '/auth/mfa/setup',
              description: 'Setup MFA for authenticated user',
              auth: true,
              response: { qrCode: 'string', secret: 'string' }
            },
            {
              method: 'POST',
              path: '/auth/mfa/setup/verify',
              description: 'Verify MFA setup code',
              auth: true,
              body: { code: 'string' },
              response: { success: 'boolean' }
            },
            {
              method: 'POST',
              path: '/auth/mfa/verify',
              description: 'Verify MFA code during login',
              auth: false,
              body: { tempToken: 'string', code: 'string' },
              response: { accessToken: 'string' }
            }
          ]
        },
        {
          category: 'Users',
          routes: [
            {
              method: 'GET',
              path: '/users/me',
              description: 'Get current user profile',
              auth: true,
              response: { id: 'number', username: 'string', role: 'string', mfaEnabled: 'boolean' }
            },
            {
              method: 'PUT',
              path: '/users/me',
              description: 'Update current user profile',
              auth: true,
              body: { username: 'string (optional)', currentPassword: 'string (optional)', newPassword: 'string (optional)' },
              response: { id: 'number', username: 'string', role: 'string' }
            },
            {
              method: 'GET',
              path: '/users',
              description: 'Get all users (Admin only)',
              auth: true,
              roles: ['ADMIN'],
              response: [{ id: 'number', username: 'string', role: 'string', mfaEnabled: 'boolean' }]
            },
            {
              method: 'GET',
              path: '/users/:id',
              description: 'Get user by ID (Admin only)',
              auth: true,
              roles: ['ADMIN'],
              response: { id: 'number', username: 'string', role: 'string', mfaEnabled: 'boolean' }
            },
            {
              method: 'POST',
              path: '/users',
              description: 'Create new user (Admin only)',
              auth: true,
              roles: ['ADMIN'],
              body: { username: 'string', password: 'string', role: 'string' },
              response: { id: 'number', username: 'string', role: 'string' }
            },
            {
              method: 'PUT',
              path: '/users/:id',
              description: 'Update user (Admin only)',
              auth: true,
              roles: ['ADMIN'],
              body: { username: 'string (optional)', password: 'string (optional)', role: 'string (optional)' },
              response: { id: 'number', username: 'string', role: 'string' }
            },
            {
              method: 'DELETE',
              path: '/users/:id',
              description: 'Delete user (Admin only)',
              auth: true,
              roles: ['ADMIN'],
              response: { success: 'boolean' }
            }
          ]
        },
        {
          category: 'Wazuh Agents',
          routes: [
            {
              method: 'GET',
              path: '/agents/status',
              description: 'Get Wazuh agents status',
              auth: true,
              roles: ['ADMIN', 'ANALYST', 'VIEWER'],
              response: [{ id: 'string', name: 'string', ip: 'string', status: 'string' }]
            }
          ]
        },
        {
          category: 'Wazuh Alerts',
          routes: [
            {
              method: 'GET',
              path: '/alerts',
              description: 'Get recent security alerts',
              auth: true,
              roles: ['ADMIN', 'ANALYST'],
              query: { severity: 'number (optional)', ip: 'string (optional)', startDate: 'string (optional)', endDate: 'string (optional)', limit: 'number (optional)' },
              response: [{ id: 'string', timestamp: 'string', rule: { level: 'number', description: 'string' }, agent: { name: 'string', ip: 'string' }, data: { src_ip: 'string', dest_ip: 'string' } }]
            },
            {
              method: 'GET',
              path: '/alerts/stats',
              description: 'Get alert statistics',
              auth: true,
              roles: ['ADMIN', 'ANALYST', 'VIEWER'],
              query: { startDate: 'string (optional)', endDate: 'string (optional)' },
              response: { total: 'number', bySeverity: 'object', byCategory: 'object' }
            }
          ]
        },
        {
          category: 'Reports',
          routes: [
            {
              method: 'POST',
              path: '/reports/generate',
              description: 'Generate security report (PDF or Excel)',
              auth: true,
              roles: ['ADMIN', 'ANALYST'],
              body: { format: 'string (pdf|excel)', severity: 'number (optional)', ip: 'string (optional)', startDate: 'string (optional)', endDate: 'string (optional)' },
              response: 'Binary file download'
            },
            {
              method: 'GET',
              path: '/reports/history',
              description: 'Get report generation history',
              auth: true,
              roles: ['ADMIN', 'ANALYST'],
              response: [{ id: 'number', filename: 'string', format: 'string', createdAt: 'string', createdBy: 'string' }]
            }
          ]
        },
        {
          category: 'Audit Logs',
          routes: [
            {
              method: 'GET',
              path: '/audit-logs',
              description: 'Get audit logs (Admin only)',
              auth: true,
              roles: ['ADMIN'],
              query: { username: 'string (optional)', action: 'string (optional)', startDate: 'string (optional)', endDate: 'string (optional)' },
              response: [{ id: 'number', username: 'string', action: 'string', timestamp: 'string', details: 'object' }]
            }
          ]
        }
      ],
      authentication: {
        type: 'JWT Bearer Token',
        description: 'Include JWT token in Authorization header: Bearer <token>',
        mfa: 'Multi-Factor Authentication available and optional per user'
      },
      roles: {
        ADMIN: 'Full access to all endpoints',
        ANALYST: 'Access to alerts, reports, and agent status',
        VIEWER: 'Read-only access to agent status and alert statistics'
      },
      rateLimiting: {
        description: 'Most endpoints have rate limiting to prevent abuse',
        default: '30 requests per minute'
      }
    };
  }
}
