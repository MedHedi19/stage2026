# Backend Spec for Cursor

## Project Goal

Build a NestJS backend for an IDS/IPS dashboard that sits between Wazuh on VM1 and a future React frontend on VM2.

This backend must:
- Authenticate users with JWT.
- Support MFA with TOTP.
- Enforce RBAC with fixed roles.
- Fetch alerts and stats from Wazuh on demand.
- Broadcast new alerts in real time over WebSocket.
- Generate PDF and Excel reports.
- Store users, roles, reports, and audit logs in MySQL only.

## Important Constraints

- Use NestJS + TypeScript.
- Use MySQL via TypeORM.
- Use `bcrypt` for password hashing.
- Use `otplib` for TOTP MFA.
- Use `qrcode` for MFA QR code generation.
- Use `pdfkit` or `puppeteer` for PDF.
- Use `exceljs` for Excel.
- Use Socket.io via `@nestjs/websockets`.
- Listen on `0.0.0.0:3000`.
- Enable CORS for the frontend.
- Do not store real-time alerts in MySQL.
- Wazuh certificate is self-signed, so HTTP calls must use `rejectUnauthorized: false`.
- Use this Wazuh base URL for now: `https://uselessly-glaucoma-velocity.ngrok-free.dev`.

## Environment Variables

```env
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=ids_app
DB_PASSWORD=
DB_DATABASE=ids_ips_db

JWT_SECRET=
JWT_EXPIRATION=1h

WAZUH_API_URL=https://uselessly-glaucoma-velocity.ngrok-free.dev
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=

PORT=3000
```

## Required Modules

### 1. auth

Responsibilities:
- `POST /auth/login`
- `POST /auth/mfa/setup`
- `POST /auth/mfa/setup/verify`
- `POST /auth/mfa/verify`
- JWT guard protection for authenticated routes

Behavior:
- Login checks username/password with bcrypt.
- If MFA is disabled, return a JWT directly.
- If MFA is enabled, return a temporary token and require MFA verification.
- MFA setup generates a secret and QR code.
- MFA verification returns the final JWT.

### 2. users

Entity: `User`

Fields:
- `id`
- `username`
- `passwordHash`
- `role` with values `admin`, `analyst`, `viewer`
- `mfaEnabled`
- `mfaSecret`
- `createdAt`

Endpoints:
- `GET /users/me`
- `GET /users`
- `GET /users/:id`
- `POST /users`
- `PUT /users/:id`
- `DELETE /users/:id`

Rules:
- CRUD endpoints are admin-only.
- Passwords must never be stored in plain text.
- MFA secret must not be returned after setup.

### 3. roles

Use fixed RBAC roles:
- `admin`: full access.
- `analyst`: read alerts and generate reports.
- `viewer`: read-only dashboard access.

Need:
- `@Roles(...)` decorator
- `RolesGuard`

### 4. wazuh

Responsibilities:
- Authenticate against Wazuh API.
- Cache Wazuh JWT.
- Fetch alerts on demand.
- Fetch stats for charts.
- Fetch agents status.

Required Wazuh API integration:
- `POST /security/user/authenticate`
- alerts search endpoint for recent events
- stats/aggregation query endpoint for dashboard graphs
- agents status endpoint

Routes:
- `GET /alerts`
- `GET /alerts/stats`
- `GET /agents/status`

Filters:
- severity
- date range
- source IP
- destination IP
- limit

Important:
- Real-time alerts belong to Wazuh, not MySQL.
- If real Wazuh is unreachable, fallback simulation is acceptable for local dev.

### 5. realtime

Responsibilities:
- Socket.io gateway.
- Poll Wazuh every 5 seconds.
- Emit `new-alert` to all connected clients.

No persistence of live alerts in MySQL.

### 6. reports

Route:
- `POST /reports/generate`

Behavior:
- Fetch alerts from Wazuh using filters.
- Generate PDF or Excel.
- Save metadata in MySQL.
- Return file download.

Also include:
- `GET /reports/history`

Store in `reports` table:
- who generated it
- when
- format
- applied filter

### 7. audit

Entity: `AuditLog`

Fields:
- `id`
- `userId`
- `action`
- `targetEntity`
- `timestamp`
- `ipAddress`

Route:
- `GET /audit-logs`

Rules:
- admin-only.
- Filter by user, action, and date range.

## Deliverables to Keep in the Repo

- Standard NestJS module structure.
- `.env.example`.
- `README.md` with startup instructions.
- `api-endpoints.http` for manual testing.
- TypeORM entities and relations.

## Not In Scope

- Frontend React app.
- Production deployment.
- Snort.
