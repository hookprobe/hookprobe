# MSSP Rootless Migration Plan

**Version:** 1.0
**Date:** 2026-01-20
**Status:** Planning

## Overview

This document outlines the migration from the current hybrid (root + rootless) deployment to a fully rootless architecture.

## Current State

```
ROOTLESS (ubuntu user):
├── hookprobe-proxy (nginx)
└── hookprobe-website (Django CMS)

ROOT (sudo):
├── mssp-django (host networking)
├── mssp-logto (host networking)
├── mssp-postgres
├── mssp-valkey
├── mssp-celery
├── mssp-clickhouse
├── mssp-victoriametrics
├── mssp-grafana
├── mssp-n8n
├── mssp-qsecbit
└── mssp-htp
```

## Target State

```
ROOTLESS (ubuntu user):
├── hookprobe-proxy (nginx)
├── hookprobe-website (Django CMS)
├── mssp-django
├── mssp-logto
├── mssp-postgres
├── mssp-valkey
├── mssp-celery
├── mssp-clickhouse
├── mssp-victoriametrics
├── mssp-grafana
├── mssp-n8n
├── mssp-qsecbit
└── mssp-htp

All on single network: hookprobe-public (172.30.0.0/24)
```

## Benefits

| Aspect | Current (Hybrid) | Target (Rootless) |
|--------|------------------|-------------------|
| Network communication | Complex (host.containers.internal) | Simple (direct container names) |
| Debugging | Hard (two namespaces) | Easy (single namespace) |
| Security | Root containers = higher privilege | Rootless = lower attack surface |
| Management | Two sets of commands (sudo/non-sudo) | Single command set |
| Compose support | Limited | Full podman-compose support |

## Pre-Migration Checklist

- [ ] Backup PostgreSQL database
- [ ] Backup ClickHouse data
- [ ] Export Grafana dashboards
- [ ] Document current container configurations
- [ ] Verify rootless podman is properly configured
- [ ] Ensure sufficient disk space for migration

## Migration Steps

### Phase 1: Backup (15 minutes)

```bash
# 1.1 Create backup directory
mkdir -p /home/ubuntu/mssp-migration-backup
cd /home/ubuntu/mssp-migration-backup

# 1.2 Backup PostgreSQL
sudo podman exec mssp-postgres pg_dumpall -U hookprobe > postgres_full_backup.sql

# 1.3 Backup secrets
sudo cp -r /etc/hookprobe/secrets/mssp ./secrets-backup

# 1.4 Backup configuration
sudo cp -r /etc/hookprobe/mssp ./config-backup

# 1.5 Export Grafana dashboards (if configured)
# curl -s http://admin:password@localhost:3000/api/dashboards/db/main | jq > grafana-main.json
```

### Phase 2: Stop Root Containers (5 minutes)

```bash
# 2.1 Stop all MSSP root containers
sudo podman stop $(sudo podman ps -q --filter "name=mssp")

# 2.2 Verify all stopped
sudo podman ps --filter "name=mssp"
# Should show no running containers
```

### Phase 3: Update podman-compose.yml (30 minutes)

Update `/home/ubuntu/hookprobe-com/podman-compose.yml` to include all MSSP services in the `mssp` profile with proper networking.

Key changes:
- All services use `hookprobe-public` network
- Static IPs assigned (172.30.0.20-172.30.0.35)
- Volume mounts for persistent data
- Environment files for configuration

### Phase 4: Deploy Rootless (10 minutes)

```bash
# 4.1 Navigate to hookprobe-com
cd /home/ubuntu/hookprobe-com

# 4.2 Pull required images
podman-compose --profile mssp pull

# 4.3 Start MSSP services
podman-compose --profile mssp up -d

# 4.4 Verify all services running
podman-compose --profile mssp ps
```

### Phase 5: Restore Data (15 minutes)

```bash
# 5.1 Wait for PostgreSQL to be ready
sleep 10

# 5.2 Restore database
podman exec -i mssp-postgres psql -U hookprobe < /home/ubuntu/mssp-migration-backup/postgres_full_backup.sql

# 5.3 Run Django migrations (if needed)
podman exec mssp-django python manage.py migrate
```

### Phase 6: Verify (10 minutes)

```bash
# 6.1 Health checks
curl -s -H "Host: mssp.hookprobe.com" http://localhost/health/
curl -s http://localhost:3001/api/status

# 6.2 Test login
curl -s -H "Host: mssp.hookprobe.com" http://localhost/login/ | grep -q "Sign In" && echo "Login page OK"

# 6.3 Check container health
podman ps --filter "name=mssp" --format "{{.Names}}: {{.Status}}"
```

### Phase 7: Cleanup (5 minutes)

```bash
# 7.1 Remove old root containers
sudo podman rm $(sudo podman ps -aq --filter "name=mssp")

# 7.2 Remove old root volumes (CAREFUL - only after verifying migration)
# sudo podman volume prune

# 7.3 Remove old root networks
# sudo podman network rm mssp-pod-001-dmz mssp-pod-002-iam ... (etc)
```

## Rollback Plan

If migration fails:

```bash
# 1. Stop rootless MSSP containers
podman-compose --profile mssp down

# 2. Restart root containers
sudo podman start $(sudo podman ps -aq --filter "name=mssp")

# 3. Verify services
sudo podman ps --filter "name=mssp"
```

## Network IP Assignments (Target)

| Container | IP Address | Port |
|-----------|------------|------|
| hookprobe-proxy | 172.30.0.2 | 80, 443 |
| hookprobe-website | 172.30.0.10 | 8000 |
| mssp-django | 172.30.0.20 | 8000 |
| mssp-postgres | 172.30.0.21 | 5432 |
| mssp-valkey | 172.30.0.22 | 6379 |
| mssp-logto | 172.30.0.23 | 3001, 3002 |
| mssp-celery | 172.30.0.24 | - |
| mssp-clickhouse | 172.30.0.25 | 8123, 9000 |
| mssp-victoriametrics | 172.30.0.26 | 8428 |
| mssp-grafana | 172.30.0.27 | 3000 |
| mssp-n8n | 172.30.0.28 | 5678 |
| mssp-qsecbit | 172.30.0.29 | 8888 |
| mssp-htp | 172.30.0.30 | 4478 |

## Post-Migration nginx.conf Updates

After migration, update nginx upstreams to use container names:

```nginx
# Before (hybrid mode)
upstream mssp {
    server host.containers.internal:8000;
}

# After (rootless mode)
upstream mssp {
    server 172.30.0.20:8000;  # Or mssp-django:8000 with DNS
}

upstream logto {
    server 172.30.0.23:3001;
}
```

## Estimated Timeline

| Phase | Duration | Downtime |
|-------|----------|----------|
| Backup | 15 min | None |
| Stop containers | 5 min | **Starts here** |
| Update compose | 30 min | Continues |
| Deploy rootless | 10 min | Continues |
| Restore data | 15 min | Continues |
| Verify | 10 min | Continues |
| Cleanup | 5 min | **Ends here** |
| **Total** | **~90 min** | **~75 min** |

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Data loss | Low | High | Full backup before migration |
| Extended downtime | Medium | Medium | Tested rollback plan |
| Network misconfiguration | Medium | Low | Pre-tested IP assignments |
| Permission issues | Low | Low | Rootless podman already tested |

## Approval

- [ ] Technical review completed
- [ ] Backup verified
- [ ] Maintenance window scheduled
- [ ] Rollback plan tested
