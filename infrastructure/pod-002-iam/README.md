# POD-002: Logto IAM Infrastructure

Logto is the centralized Identity and Access Management (IAM) provider for all HookProbe services.

## Architecture

```
POD-002 (IAM Network: 172.20.2.0/24)
├── logto           (172.20.2.10:3001) - Logto Core API
├── logto-admin     (172.20.2.10:3002) - Logto Admin Console
└── Uses POD-003 PostgreSQL for data storage
```

## Quick Start

```bash
# Deploy Logto
cd /home/ubuntu/hookprobe/infrastructure/pod-002-iam
sudo podman-compose up -d

# Access Admin Console
open http://localhost:3002
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOGTO_ENDPOINT` | Public URL for Logto | `http://localhost:3001` |
| `LOGTO_ADMIN_ENDPOINT` | Admin console URL | `http://localhost:3002` |
| `POSTGRES_HOST` | PostgreSQL host | `10.200.3.12` |
| `POSTGRES_DB` | Database name | `logto` |
| `POSTGRES_USER` | Database user | `logto` |
| `POSTGRES_PASSWORD` | Database password | (required) |

### OIDC Applications

After deployment, create two OIDC applications in Logto Admin Console:

1. **hookprobe.com** (Traditional Web App)
   - Redirect URI: `https://hookprobe.com/oidc/callback/`
   - Scopes: `openid profile email roles`

2. **mssp.hookprobe.com** (Traditional Web App)
   - Redirect URI: `https://mssp.hookprobe.com/oidc/callback/`
   - Scopes: `openid profile email roles`

### Roles

Create the following roles in Logto:

| Role | Description |
|------|-------------|
| `admin` | Full access to all services |
| `soc_analyst` | MSSP dashboard access only |
| `editor` | CMS/blog editing access |
| `customer` | Shop/merchandise access |

## Database Setup

Logto uses PostgreSQL in POD-003. Create the database:

```sql
CREATE DATABASE logto;
CREATE USER logto WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE logto TO logto;
```

## Ports

| Port | Service | Protocol |
|------|---------|----------|
| 3001 | Logto API | HTTP |
| 3002 | Logto Admin | HTTP |

## Health Check

```bash
curl http://localhost:3001/health
```

## Backup

Logto data is stored in PostgreSQL. Backup the `logto` database:

```bash
pg_dump -h 10.200.3.12 -U logto logto > logto_backup.sql
```
