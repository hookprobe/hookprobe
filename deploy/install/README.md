# Installation Utility Scripts

**Helper scripts for HookProbe deployment and maintenance**

This directory contains utility scripts used during installation, configuration, and maintenance of HookProbe.

---

## 📁 Available Scripts

```
scripts/
├── validate-config.sh      # Configuration validation
├── gdpr-retention.sh       # Automated data retention cleanup
├── backup.sh               # Backup and restore utilities
└── update-containers.sh    # Container image updates
```

---

## ✅ Configuration Validation (`validate-config.sh`)

Validates HookProbe configuration files before deployment.

### What It Validates

1. **Shell Syntax**: Checks for bash syntax errors
2. **Network Configuration**: Validates IP addresses, subnets, VXLANs
3. **Credentials**: Ensures passwords are set and not default
4. **Deployment Type**: Validates deployment mode settings
5. **Version Consistency**: Checks version compatibility

### Usage

```bash
# Validate edge configuration
./install/scripts/validate-config.sh edge

# Validate cloud configuration
./install/scripts/validate-config.sh cloud

# Validate specific file
./install/scripts/validate-config.sh --file install/edge/config.sh
```

### Output Example

```
========================================
CONFIGURATION VALIDATION
========================================

[✓] Shell syntax: PASS
[✓] Network config: VALID
[✗] Passwords: DEFAULT DETECTED
    - POSTGRES_PASSWORD still set to default
    - VXLAN_PSK not changed
[✓] Deployment type: edge
[✓] Version: 5.0

Result: FAILED (2 errors)
Please fix errors before proceeding.
```

---

## 🔐 GDPR Data Retention (`gdpr-retention.sh`)

Automated data retention and privacy compliance script.

### Features

- Automatic deletion of expired data
- IP/MAC anonymization after retention period
- Compliance reporting
- Audit logging

### What Gets Cleaned

| Data Type | Default Retention | Action |
|-----------|-------------------|--------|
| **Network Flows** | 30 days | Delete files + ClickHouse DELETE |
| **IDS Alerts** | 365 days | Delete files + ClickHouse DELETE |
| **WAF Logs** | 90 days | Delete files + ClickHouse DELETE |
| **Qsecbit Scores** | 90 days | ClickHouse DELETE |
| **User Accounts** | 365 days inactive | Soft delete → permanent delete |

### Usage

```bash
# Manual run (dry-run mode)
sudo ./install/scripts/gdpr-retention.sh --dry-run

# Actual cleanup
sudo ./install/scripts/gdpr-retention.sh

# Automated (cron job)
sudo crontab -e
# Add: 0 2 * * * /home/user/hookprobe/install/scripts/gdpr-retention.sh
```

### Output

```
========================================
GDPR DATA RETENTION CLEANUP
Date: 2025-01-15 02:00:00
========================================

[INFO] Cleaning network flows older than 30 days...
  - Deleted: 15.2GB (23,456 files)

[INFO] Cleaning security logs older than 90 days...
  - Deleted: 8.7GB (12,345 files)

[INFO] Anonymizing old data...
  - Anonymized: 5,678 IP addresses
  - Anonymized: 3,421 MAC addresses

[INFO] Cleaning inactive accounts...
  - Deleted: 23 accounts

========================================
CLEANUP SUMMARY
========================================
Total disk freed: 23.9GB
Items processed: 41,254
Duration: 2m 15s

Compliance report: /var/log/hookprobe/compliance-reports/2025-01-15.txt
```

---

## 💾 Backup & Restore (`backup.sh`)

Backup and restore HookProbe configuration and data.

### What Gets Backed Up

1. **Configuration Files**:
   - install/edge/config.sh
   - install/cloud/config.sh
   - All POD configurations

2. **Databases**:
   - PostgreSQL (full dump)
   - ClickHouse (schema + data)
   - Redis (RDB snapshot)

3. **Certificates & Keys**:
   - SSL/TLS certificates
   - DKIM keys (if email installed)
   - VXLAN PSK encryption keys

4. **Custom Dashboards**:
   - Grafana dashboards
   - Custom queries

### Usage

```bash
# Full backup
sudo ./install/scripts/backup.sh --full

# Configuration only
sudo ./install/scripts/backup.sh --config

# Database only
sudo ./install/scripts/backup.sh --database

# Restore from backup
sudo ./install/scripts/backup.sh --restore /backup/hookprobe-2025-01-15.tar.gz
```

### Backup Location

```bash
# Default: /var/backups/hookprobe/
ls -lh /var/backups/hookprobe/
-rw------- 1 root root 2.3G Jan 15 02:00 hookprobe-full-2025-01-15.tar.gz
-rw------- 1 root root 124M Jan 14 02:00 hookprobe-config-2025-01-14.tar.gz
```

### Automated Backups

```bash
# Daily configuration backup
0 2 * * * /home/user/hookprobe/install/scripts/backup.sh --config

# Weekly full backup
0 3 * * 0 /home/user/hookprobe/install/scripts/backup.sh --full

# Monthly off-site sync
0 4 1 * * rsync -avz /var/backups/hookprobe/ backup-server:/remote/hookprobe/
```

---

## 🔄 Container Updates (`update-containers.sh`)

Update HookProbe container images to latest versions.

### Features

- Check for image updates
- Pull latest images
- Recreate containers with new images
- Rollback capability
- Zero-downtime updates (rolling updates)

### Usage

```bash
# Check for updates (dry-run)
sudo ./install/scripts/update-containers.sh --check

# Update all containers
sudo ./install/scripts/update-containers.sh --all

# Update specific POD
sudo ./install/scripts/update-containers.sh --pod 001

# Rollback to previous version
sudo ./install/scripts/update-containers.sh --rollback
```

### Update Process

```
1. Pull new images
   ↓
2. Stop old containers
   ↓
3. Create new containers with same config
   ↓
4. Verify health
   ↓
5. Remove old images (optional)
```

### Output Example

```
========================================
CONTAINER UPDATE CHECK
========================================

[INFO] Checking for updates...

POD-001 (Web DMZ):
  - nginx:1.27-alpine → 1.27.1-alpine (UPDATE AVAILABLE)
  - django:latest → latest (NO UPDATE)

POD-005 (Monitoring):
  - grafana:11.4.0 → 11.5.0 (UPDATE AVAILABLE)
  - victoriametrics:latest → latest (NO UPDATE)

Total updates available: 2

Proceed with update? [y/N]
```

---

## 🛠️ Script Development

### Adding New Scripts

1. Create script in `install/scripts/`
2. Add shebang and error handling:
   ```bash
   #!/bin/bash
   set -e  # Exit on error
   set -u  # Exit on undefined variable
   ```

3. Source common functions:
   ```bash
   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
   source "$SCRIPT_DIR/../common/functions.sh"
   ```

4. Add help text:
   ```bash
   show_help() {
       echo "Usage: $0 [OPTIONS]"
       echo "Options:"
       echo "  --help    Show this help"
       echo "  --dry-run Simulate without changes"
   }
   ```

5. Make executable:
   ```bash
   chmod +x install/scripts/your-script.sh
   ```

---

## 🔧 Common Patterns

### Error Handling

```bash
# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

# Check if command exists
if ! command -v podman &> /dev/null; then
    echo "ERROR: podman not found"
    exit 1
fi

# Trap errors
trap 'echo "ERROR: Script failed at line $LINENO"' ERR
```

### Logging

```bash
# Use common logging functions
log_info "Starting backup..."
log_warn "Old backup found, overwriting..."
log_error "Backup failed"
log_success "Backup completed successfully"
```

### Progress Indicators

```bash
# Show spinner for long operations
show_spinner "Downloading images..." &
SPINNER_PID=$!

podman pull nginx:latest

kill $SPINNER_PID
echo "✓ Download complete"
```

---

## 📊 Script Execution Logs

All scripts log to `/var/log/hookprobe/`:

```bash
# View recent script executions
tail -f /var/log/hookprobe/install.log
tail -f /var/log/hookprobe/gdpr-retention.log
tail -f /var/log/hookprobe/backup.log
tail -f /var/log/hookprobe/update.log
```

---

## 🧪 Testing Scripts

### Syntax Check

```bash
# Check all scripts for syntax errors
for script in install/scripts/*.sh; do
    echo "Checking $script..."
    bash -n "$script" && echo "✓ OK" || echo "✗ SYNTAX ERROR"
done
```

### ShellCheck Linting

```bash
# Install ShellCheck
sudo dnf install ShellCheck

# Lint all scripts
shellcheck install/scripts/*.sh
```

### Dry-Run Mode

Most scripts support `--dry-run` for testing:

```bash
sudo ./install/scripts/gdpr-retention.sh --dry-run
sudo ./install/scripts/backup.sh --dry-run --full
sudo ./install/scripts/update-containers.sh --check
```

---

## 📚 Documentation

- **Main Installer**: [../install.sh](../../install.sh)
- **Configuration**: [../common/README.md](../common/README.md)
- **GDPR Compliance**: [../../docs/GDPR.md](../../docs/GDPR.md)
- **Contributing**: [../../docs/CONTRIBUTING.md](../../docs/CONTRIBUTING.md)

---

**Installation Utility Scripts** - *Automation for Reliable Deployments*

Built with ❤️ for system administrators and DevOps teams
