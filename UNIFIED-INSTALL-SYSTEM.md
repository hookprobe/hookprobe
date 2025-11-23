# HookProbe Unified Installation System

**Version**: 5.0
**Date**: 2025-11-23
**Purpose**: Overview of the new unified installation, update, and management system

---

## Overview

HookProbe v5.0 introduces a **three-layer unified installation system** that simplifies deployment, monitoring, and maintenance through systemd integration and automated management.

---

## Architecture

### Layer 1: Bootstrap Installer

**Script**: `Scripts/autonomous/install/hookprobe-bootstrap.sh`

**Purpose**: One-time installation script that sets up the entire system

**Features**:
- ✅ Environment detection (OS, architecture, kernel, NICs)
- ✅ Dependency installation (Podman, OVS, Python packages)
- ✅ Directory structure setup
- ✅ systemd service deployment
- ✅ Initial provisioning
- ✅ Validation and health checks

**Usage**:
```bash
cd Scripts/autonomous/install/
sudo ./hookprobe-bootstrap.sh
```

---

### Layer 2: systemd Services

#### 1. hookprobe-provision.service

**Location**: `Scripts/autonomous/install/systemd/hookprobe-provision.service`

**Purpose**: Runs at install and on each boot for auto-repair

**Responsibilities**:
- Install/verify tools and dependencies
- Build XDP/eBPF programs
- Detect and verify NIC capabilities
- Apply kernel settings (sysctl)
- Verify required services (Podman, OVS)
- Create/verify directory structure

**Script**: `Scripts/autonomous/install/provision.sh`

**When it runs**:
- During initial installation
- On every system boot
- When manually triggered: `sudo systemctl start hookprobe-provision.service`

#### 2. hookprobe-agent.service

**Location**: `Scripts/autonomous/install/systemd/hookprobe-agent.service`

**Purpose**: Long-running monitoring daemon

**Responsibilities**:
- Energy monitoring (RAPL + per-PID tracking)
- NIC monitoring and statistics
- XDP/eBPF DDoS mitigation (if enabled)
- Qsecbit cyber resilience metric calculation
- Anomaly detection and alerting
- Telemetry export (VictoriaMetrics, ClickHouse)
- HTTP health check endpoint (port 8888)

**Script**: `Scripts/autonomous/qsecbit/qsecbit-agent.py`

**Environment variables**:
- `XDP_ENABLED` - Enable XDP DDoS mitigation (default: false)
- `DEPLOYMENT_ROLE` - "server" or "endpoint" (default: server)

**HTTP endpoints**:
- `http://localhost:8888/health` - Health check
- `http://localhost:8888/metrics` - Current metrics (JSON)

#### 3. hookprobe-update.service + hookprobe-update.timer

**Location**:
- `Scripts/autonomous/install/systemd/hookprobe-update.service`
- `Scripts/autonomous/install/systemd/hookprobe-update.timer`

**Purpose**: Automated weekly updates from GitHub

**Features**:
- Pulls latest changes from GitHub
- Creates automatic backups
- Re-provisions system
- Restarts services
- Verifies health
- Automatic rollback on failure

**Script**: `Scripts/autonomous/install/update.sh`

**Schedule**: Weekly on Sundays at 3:00 AM (configurable)

**Enable/Disable**:
```bash
sudo hookprobe-ctl enable-autoupdate
sudo hookprobe-ctl disable-autoupdate
```

#### 4. hookprobe-uninstall.service

**Location**: `Scripts/autonomous/install/systemd/hookprobe-uninstall.service`

**Purpose**: Clean uninstallation of all HookProbe components

**Removes**:
- systemd units
- XDP programs from all interfaces
- Podman containers and PODs
- OVS bridge (qsec-bridge)
- Firewall rules
- Kernel settings (sysctl)
- Files and directories

**Script**: `Scripts/autonomous/install/cleanup.sh`

**Usage**:
```bash
sudo hookprobe-ctl uninstall
```

---

### Layer 3: Management CLI

**Script**: `Scripts/autonomous/install/hookprobe-ctl`

**Purpose**: Unified command-line interface for all HookProbe operations

**Commands**:

| Command | Description |
|---------|-------------|
| `status` | Show service status |
| `start` | Start HookProbe services |
| `stop` | Stop HookProbe services |
| `restart` | Restart HookProbe services |
| `enable` | Enable auto-start on boot |
| `disable` | Disable auto-start |
| `logs [service] [-f]` | View logs (follow with -f) |
| `update` | Run manual update |
| `enable-autoupdate` | Enable weekly auto-updates |
| `disable-autoupdate` | Disable auto-updates |
| `metrics` | Show current metrics |
| `health` | Check agent health |
| `uninstall` | Remove HookProbe completely |
| `version` | Show version |
| `help` | Show help |

**Examples**:
```bash
# Check status
hookprobe-ctl status

# View live logs
hookprobe-ctl logs -f

# Enable auto-updates
sudo hookprobe-ctl enable-autoupdate

# View metrics
hookprobe-ctl metrics
```

---

## Supporting Scripts

### provision.sh

**Location**: `Scripts/autonomous/install/provision.sh`

**Purpose**: System provisioning and configuration

**Functions**:
- OS detection (RHEL vs Debian)
- NIC detection and capability assessment
- XDP support detection
- Kernel settings application
- Service verification
- Directory structure creation

**Called by**: `hookprobe-provision.service`

### cleanup.sh

**Location**: `Scripts/autonomous/install/cleanup.sh`

**Purpose**: Complete system cleanup and uninstallation

**Features**:
- Safe service shutdown
- XDP program removal
- Container/POD cleanup
- Network configuration removal
- Firewall rule cleanup
- File/directory removal
- Verification of cleanup

**Called by**: `hookprobe-uninstall.service` or `hookprobe-ctl uninstall`

### update.sh

**Location**: `Scripts/autonomous/install/update.sh`

**Purpose**: Automated updates from GitHub with rollback

**Features**:
- Automatic backup before update
- Git pull from configured branch
- File synchronization
- Service restart
- Health verification
- Automatic rollback on failure
- Backup retention (keeps last 5)

**Called by**: `hookprobe-update.service` or `hookprobe-ctl update`

### qsecbit-agent.py

**Location**: `Scripts/autonomous/qsecbit/qsecbit-agent.py`

**Purpose**: Main monitoring daemon

**Components integrated**:
- `qsecbit.py` - Cyber resilience metric calculation
- `energy_monitor.py` - RAPL + per-PID energy tracking
- `xdp_manager.py` - XDP/eBPF DDoS mitigation
- `nic_detector.py` - NIC capability detection

**Features**:
- HTTP health check server (port 8888)
- Metrics collection and export
- Alert processing
- Graceful shutdown handling
- Component initialization and error handling

**Called by**: `hookprobe-agent.service`

---

## File Structure

```
hookprobe/
├── Scripts/autonomous/install/
│   ├── hookprobe-bootstrap.sh        # Layer 1: Bootstrap installer
│   ├── hookprobe-ctl                 # Layer 3: Management CLI
│   ├── provision.sh                  # Provisioning script
│   ├── cleanup.sh                    # Cleanup script
│   ├── update.sh                     # Update script
│   ├── systemd/                      # Layer 2: systemd units
│   │   ├── hookprobe-provision.service
│   │   ├── hookprobe-agent.service
│   │   ├── hookprobe-update.service
│   │   ├── hookprobe-update.timer
│   │   └── hookprobe-uninstall.service
│   ├── QUICK-START.md                # Quick start guide
│   └── setup.sh                      # Original POD deployment (still available)
├── Scripts/autonomous/qsecbit/
│   └── qsecbit-agent.py              # Monitoring daemon
├── Documents/
│   ├── INSTALLATION.md               # Comprehensive installation guide
│   └── (other docs...)
└── UNIFIED-INSTALL-SYSTEM.md         # This file
```

---

## Installation Flow

```
1. User runs: sudo ./hookprobe-bootstrap.sh
   ↓
2. Bootstrap installer:
   - Detects environment
   - Installs dependencies
   - Creates directories
   - Copies files to /opt/hookprobe
   - Installs systemd units
   - Enables services
   ↓
3. hookprobe-provision.service runs:
   - Provisions system
   - Detects NICs
   - Applies kernel settings
   - Verifies everything
   ↓
4. hookprobe-agent.service starts:
   - Initializes components
   - Starts monitoring
   - Exposes health endpoint
   ↓
5. System ready!
   - User can use hookprobe-ctl to manage
   - Agent monitors continuously
   - Auto-updates (if enabled)
```

---

## Configuration Files

**System locations**:
- `/opt/hookprobe/` - Installation directory
  - `scripts/` - Bash scripts
  - `agent/` - Python agent
  - `xdp/` - XDP programs
  - `config/` - Runtime configuration
  - `data/` - Data files
- `/etc/hookprobe/` - Configuration directory
  - `network-config.sh` - Main configuration
- `/var/log/hookprobe/` - Logs
  - `agent.log` - Agent logs
  - `provision.log` - Provision logs
  - `update.log` - Update logs
  - `cleanup.log` - Cleanup logs

**systemd units**:
- `/etc/systemd/system/hookprobe-*.service`
- `/etc/systemd/system/hookprobe-*.timer`

---

## Key Features

### 1. Auto-Repair on Boot

The `hookprobe-provision.service` runs on every boot, ensuring:
- Services are installed and configured
- Network settings are applied
- XDP programs are loaded (if enabled)
- System is in a known-good state

This makes HookProbe resilient to:
- Kernel updates
- Network configuration changes
- Unexpected reboots
- Configuration drift

### 2. Health Monitoring

The agent exposes HTTP endpoints for health checks:

```bash
# Health check
curl http://localhost:8888/health
{
  "status": "healthy",
  "version": "5.0",
  "uptime": 3600
}

# Metrics
curl http://localhost:8888/metrics
{
  "timestamp": 1700000000,
  "uptime": 3600,
  "energy": {...},
  "xdp": {...},
  "qsecbit": {...}
}
```

This enables:
- External monitoring (Grafana, Prometheus)
- Load balancer health checks
- Automated failover
- Status dashboards

### 3. Safe Updates with Rollback

The update system includes:
- Automatic backups before updates
- Health verification after updates
- Automatic rollback on failure
- Backup retention (keeps last 5)

Update process:
1. Create backup
2. Pull from GitHub
3. Apply changes
4. Re-provision
5. Restart services
6. Verify health
7. Rollback if failed

### 4. XDP/eBPF Integration

XDP can be enabled per-deployment:

```bash
# Enable XDP
sudo systemctl edit hookprobe-agent.service

# Add:
[Service]
Environment="XDP_ENABLED=true"

# Restart
sudo systemctl daemon-reload
sudo systemctl restart hookprobe-agent.service
```

XDP automatically:
- Detects NIC capabilities
- Selects optimal mode (XDP-DRV or XDP-SKB)
- Loads eBPF programs
- Provides real-time statistics

### 5. GDPR Compliance

Privacy settings are enabled by default:
- IP anonymization (last octet masked)
- MAC anonymization (device ID masked)
- No payload collection
- Configurable retention periods

See `GDPR.md` for complete compliance guide.

---

## Compatibility

### Operating Systems

**RHEL-based**:
- RHEL 10
- Fedora 40+
- CentOS Stream 9+
- Rocky Linux 9+
- AlmaLinux 9+

**Debian-based**:
- Debian 12+
- Ubuntu 22.04+ / 24.04+

### Architectures

- x86_64 (Intel/AMD)
- ARM64 (Raspberry Pi 4/5, Rockchip SBCs)

### Deployment Targets

- Physical hardware (Intel N100, SBCs)
- Virtual machines (KVM, VMware, Proxmox)
- Cloud instances (AWS, Azure, GCP)

**Not supported**:
- Docker containers (networking conflicts)
- LXC containers (networking limitations)
- ARMv7 (32-bit ARM)

---

## Migration from v4.x

For users upgrading from HookProbe v4.x:

1. **Backup existing installation**:
   ```bash
   sudo tar -czf hookprobe-v4-backup.tar.gz /opt/hookprobe /etc/hookprobe
   ```

2. **Uninstall v4.x**:
   ```bash
   sudo ./uninstall.sh
   ```

3. **Install v5.0**:
   ```bash
   sudo ./hookprobe-bootstrap.sh
   ```

4. **Restore configuration** (if needed):
   ```bash
   # Copy your old network-config.sh settings to /etc/hookprobe/network-config.sh
   ```

5. **Verify**:
   ```bash
   hookprobe-ctl status
   ```

---

## Development

For developers and contributors:

**Testing the installer**:
```bash
# Clean environment
sudo ./cleanup.sh

# Test installation
sudo ./hookprobe-bootstrap.sh

# Verify
hookprobe-ctl status
hookprobe-ctl health
```

**Modifying scripts**:
1. Edit scripts in `Scripts/autonomous/install/`
2. Test changes
3. Update documentation
4. Commit changes

**Adding new systemd services**:
1. Create `.service` file in `systemd/`
2. Update `hookprobe-bootstrap.sh` to install it
3. Update `hookprobe-ctl` to manage it
4. Update documentation

See `CLAUDE.md` for complete development guidelines.

---

## Troubleshooting

### Common Issues

**Services won't start**:
```bash
# Re-provision
sudo systemctl start hookprobe-provision.service

# Check logs
journalctl -u hookprobe-agent.service --no-pager -n 50
```

**XDP not loading**:
```bash
# Check NIC capabilities
cat /opt/hookprobe/config/nic.conf

# View logs
hookprobe-ctl logs -f
```

**Update fails**:
```bash
# Check if backup exists
ls -l /opt/hookprobe-backups/

# Manual rollback
sudo cp -r /opt/hookprobe-backups/<latest>/* /opt/hookprobe/
sudo hookprobe-ctl restart
```

### Log Files

- `/var/log/hookprobe/agent.log`
- `/var/log/hookprobe/provision.log`
- `/var/log/hookprobe/update.log`
- `/var/log/hookprobe/cleanup.log`

Or via journalctl:
```bash
sudo journalctl -u 'hookprobe-*' -f
```

---

## Future Enhancements

Planned improvements for future versions:

- [ ] Web UI for management (alternative to CLI)
- [ ] Container images for rapid deployment
- [ ] Multi-node orchestration
- [ ] Automated failover
- [ ] Integration with CI/CD pipelines
- [ ] Ansible/Terraform modules
- [ ] Kubernetes operator

---

## Documentation

- **Quick Start**: `Scripts/autonomous/install/QUICK-START.md`
- **Full Installation Guide**: `Documents/INSTALLATION.md`
- **Development Guide**: `CLAUDE.md`
- **GDPR Compliance**: `GDPR.md`
- **Main README**: `README.md`

---

## Support

- **GitHub**: https://github.com/hookprobe/hookprobe
- **Issues**: https://github.com/hookprobe/hookprobe/issues
- **Security**: qsecbit@hookprobe.com

---

**HookProbe v5.0** - Unified Installation System
**Date**: 2025-11-23
