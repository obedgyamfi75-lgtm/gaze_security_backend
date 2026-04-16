# GAZE Security Platform - Backend API

Enterprise-grade security assessment and vulnerability management API built with Flask, PostgreSQL, and Redis.

## Features

- **Security-First Architecture**: Argon2id password hashing, TOTP MFA, rate limiting, CSRF protection
- **RESTful JSON API**: Clean API design for frontend integration
- **Session Management**: Redis-backed secure sessions with cookie authentication
- **Role-Based Access Control**: Granular permissions system
- **Audit Logging**: Comprehensive activity tracking
- **PDF Generation**: Sandboxed WeasyPrint for secure report generation

## Quick Start

### Prerequisites

- Docker & Docker Compose
- (Optional) Python 3.12+ for local development

### Production Deployment

```bash
# 1. Clone and enter directory
cd hubtel-secops-backend

# 2. Create environment file
cp .env.example .env

# 3. Generate secure secrets
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
echo "DB_PASS=$(openssl rand -hex 16)" >> .env
echo "REDIS_PASS=$(openssl rand -hex 16)" >> .env

# 4. Build and start services
docker compose build
docker compose up -d

# 5. Initialize database (first time only)
docker compose exec app flask db upgrade
docker compose exec app flask seed-admin

# 6. Check health
curl http://localhost/api/health
```

### Build Output

Docker Compose creates the following containers:
- `secops-app` - Flask application (Gunicorn)
- `secops-postgres` - PostgreSQL 16 database
- `secops-redis` - Redis 7 session store
- `secops-caddy` - Caddy reverse proxy (TLS termination)

### Manual Docker Build

```bash
# Build app image only
docker build -f docker/app/Dockerfile -t hubtel-secops-backend .

# Run with external Postgres/Redis
docker run -p 8000:8000 \
  -e SECRET_KEY=your-secret-key \
  -e DATABASE_URL=postgresql://user:pass@host:5432/db \
  -e REDIS_URL=redis://:pass@host:6379/0 \
  hubtel-secops-backend
```

The API will be available at `http://localhost/api`

### Development Setup

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# 2. Install dependencies
pip install -r requirements/base.txt -r requirements/dev.txt

# 3. Start PostgreSQL and Redis (via Docker)
docker compose -f docker compose.dev.yml up -d

# 4. Set environment variables
export FLASK_ENV=development
export SECRET_KEY=dev-secret-key-min-32-characters-long
export DATABASE_URL=postgresql://secops:secops@localhost:5432/secops
export REDIS_URL=redis://:redispass@localhost:6379/0

# 5. Initialize database
flask db upgrade
flask seed-admin

# 6. Run development server
flask run --port 8000
```

## API Documentation

### Authentication

All API endpoints require authentication via session cookie. Login first to establish a session.

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "admin@hubtel.com",
  "password": "your-password"
}

# Response (success, no MFA):
{
  "success": true,
  "data": {
    "user": { "id": "...", "email": "...", "role": "admin" },
    "requires_mfa": false
  }
}

# Response (MFA required):
{
  "success": true,
  "data": {
    "user": null,
    "requires_mfa": true
  }
}
```

#### MFA Verification
```bash
POST /api/auth/mfa/verify
Content-Type: application/json

{
  "code": "123456"
}
```

#### Get Current User
```bash
GET /api/auth/me
```

#### Logout
```bash
POST /api/auth/logout
```

### Dashboard

```bash
GET /api/dashboard/stats
GET /api/dashboard/vulnerability-trend?months=6
GET /api/dashboard/recent-activity?limit=10
GET /api/dashboard/sla-status
```

### Assessments

```bash
GET    /api/assessments                    # List assessments
POST   /api/assessments                    # Create assessment
GET    /api/assessments/:id                # Get assessment
PUT    /api/assessments/:id                # Update assessment
DELETE /api/assessments/:id                # Delete assessment
PATCH  /api/assessments/:id/status         # Update status
GET    /api/assessments/:id/findings       # Get findings for assessment
POST   /api/assessments/:id/report         # Generate report
```

### Findings

```bash
GET    /api/findings                       # List findings (with filters)
POST   /api/findings                       # Create finding
GET    /api/findings/:id                   # Get finding
PUT    /api/findings/:id                   # Update finding
DELETE /api/findings/:id                   # Delete finding
PATCH  /api/findings/:id/status            # Update status
POST   /api/findings/bulk/status           # Bulk status update
POST   /api/findings/:id/evidence          # Upload evidence
GET    /api/findings/:id/evidence          # List evidence
DELETE /api/findings/:id/evidence/:eid     # Delete evidence
```

### Assets

```bash
GET    /api/assets                         # List assets
POST   /api/assets                         # Create asset
GET    /api/assets/:id                     # Get asset
PUT    /api/assets/:id                     # Update asset
DELETE /api/assets/:id                     # Delete asset
GET    /api/assets/:id/findings            # Get findings for asset
GET    /api/assets/:id/security-score      # Get security score
```

### Reports

```bash
GET    /api/reports                        # List reports
POST   /api/reports/generate               # Generate report
GET    /api/reports/:id                    # Get report info
GET    /api/reports/:id/download           # Download report
DELETE /api/reports/:id                    # Delete report
```

### Admin

```bash
GET    /api/admin/users                    # List users
POST   /api/admin/users                    # Create user
GET    /api/admin/users/:id                # Get user
PUT    /api/admin/users/:id                # Update user
DELETE /api/admin/users/:id                # Delete user
POST   /api/admin/users/:id/reset-password # Reset password
GET    /api/admin/audit-logs               # List audit logs
```

## API Response Format

### Success Response
```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "page": 1,
    "perPage": 10,
    "total": 100,
    "totalPages": 10
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message here"
}
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask secret key (min 32 chars) | - | Yes |
| `DATABASE_URL` | PostgreSQL connection URL | - | Yes |
| `REDIS_URL` | Redis connection URL | - | Yes |
| `FLASK_ENV` | Environment (development/production) | production | No |
| `CORS_ORIGINS` | Allowed CORS origins (comma-separated) | http://localhost:3000 | No |
| `ALLOWED_HOSTS` | Allowed host headers | localhost | No |
| `LOG_LEVEL` | Logging level | INFO | No |

## Project Structure

```
hubtel-secops-backend/
├── app/
│   ├── __init__.py          # Application factory
│   ├── models/              # SQLAlchemy models
│   │   ├── user.py
│   │   ├── asset.py
│   │   ├── assessment.py
│   │   └── finding.py
│   ├── routes/              # API blueprints
│   │   ├── api_auth.py      # JSON auth endpoints
│   │   ├── auth.py          # HTML auth (legacy)
│   │   ├── dashboard.py
│   │   ├── assessments.py
│   │   ├── findings.py
│   │   ├── assets.py
│   │   ├── reports.py
│   │   └── admin.py
│   ├── security/            # Security utilities
│   │   ├── auth_service.py
│   │   ├── audit_logger.py
│   │   └── validators.py
│   ├── services/            # Business logic
│   └── templates/           # Jinja2 templates (reports)
├── migrations/              # Alembic migrations
├── docker/
│   ├── app/Dockerfile
│   ├── caddy/Caddyfile
│   └── postgres/init.sql
├── requirements/
│   ├── base.txt
│   ├── dev.txt
│   └── security.txt
├── config.py                # Configuration
├── run.py                   # Entry point
├── docker compose.yml       # Production compose
└── docker compose.dev.yml   # Development compose
```

## Security Features

- **Password Security**: Argon2id hashing, zxcvbn strength checking, breach detection
- **MFA**: TOTP with backup codes
- **Session Security**: Redis-backed, secure cookies, session fixation protection
- **Rate Limiting**: Redis-backed per-endpoint limits
- **CORS**: Configurable origins with credentials support
- **Headers**: Strict CSP, HSTS, X-Frame-Options via Talisman
- **Input Validation**: Pydantic schemas, sanitization
- **Audit Logging**: All security events logged

## Connecting Frontend

The frontend should connect to this API at `http://localhost:8000/api` (development) or `https://your-domain.com/api` (production).

Configure frontend environment:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

Ensure CORS origins include your frontend URL:
```env
CORS_ORIGINS=http://localhost:3000,https://your-frontend-domain.com
```

## Database Migrations

```bash
# Create migration
flask db migrate -m "Description"

# Apply migrations
flask db upgrade

# Rollback
flask db downgrade
```

## Troubleshooting

### CORS Errors
- Check `CORS_ORIGINS` includes your frontend URL
- Ensure credentials: 'include' is set in frontend fetch calls

### Session Not Persisting
- Verify Redis is running: `docker compose ps`
- Check cookie settings match your domain
- For local dev, ensure same localhost domain

### Database Connection
- Check `DATABASE_URL` format: `postgresql://user:pass@host:5432/db`
- Verify PostgreSQL is healthy: `docker compose exec postgres pg_isready`

## License

Proprietary - GAZE Limited