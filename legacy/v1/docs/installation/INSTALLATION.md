# HookProbe Unified Installation Guide

**Version**: 5.0
**Last Updated**: 2025-11-23

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
- [Post-Installation](#post-installation)
- [Management](#management)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

---

## Overview

HookProbe v5.0 introduces a **unified installation system** based on systemd services for simplified deployment, monitoring, and maintenance.

### Architecture Layers

**Layer 1: Bootstrap Installer**
- One-time setup script (`hookprobe-bootstrap.sh`)
- Detects environment (OS, architecture, kernel, NICs)
- Installs dependencies
- Deploys systemd units
- Runs initial provisioning

**Layer 2: systemd Services**
- `hookprobe-provision.service` - Runs at install and boot for auto-repair
- `hookprobe-agent.service` - Long-running monitoring daemon
- `hookprobe-update.service` - Auto-update service (triggered by timer)
- `hookprobe-update.timer` - Weekly update scheduler (optional)

**Layer 3: Management CLI**
- `hookprobe-ctl` - Unified command-line interface for all operations

### What's New in v5.0

✅ **Systemd integration** - No more manual script execution
✅ **Auto-repair** - Provision service runs on each boot
✅ **Auto-updates** - Optional weekly updates from GitHub
✅ **Health monitoring** - HTTP endpoint for health checks
✅ **Unified management** - Single CLI tool for all operations
✅ **XDP/eBPF integration** - Kernel-level DDoS mitigation
✅ **Energy monitoring** - RAPL + per-PID tracking with network direction awareness
✅ **GDPR compliance** - Privacy-by-design and by-default

---

## Prerequisites

### Supported Operating Systems

**Debian-based** (Supported in v5.x):
- Ubuntu 22.04+ / 24.04+
- Debian 11+ / 12+
- Raspberry Pi OS (Bookworm)
- Linux Mint, Pop!_OS, and other Ubuntu/Debian derivatives

> **Note**: RHEL-based systems (RHEL, Fedora, CentOS, Rocky Linux, AlmaLinux) are **not supported** due to OpenVSwitch availability limitations (OVS available on RHEL 9 but not RHEL 10). Support planned for future release.

### Supported Architectures

- **x86_64** (Intel/AMD 64-bit)
- **ARM64** (ARMv8 - Raspberry Pi 4/5, Rockchip SBCs)

⚠️ **Not Supported**: ARMv7 (32-bit ARM)

### Hardware Requirements

**Minimum**:
- 2 CPU cores
- 4 GB RAM
- 20 GB disk space
- 1 Gbps network interface

**Recommended (Edge Deployment)**:
- Intel N100 Mini PC (4 cores, 8 threads)
- 8 GB RAM
- 64 GB NVMe SSD
- Intel I226-V 2.5 Gbps NIC (built-in)

**Recommended (Cloud Backend)**:
- 8+ CPU cores
- 16+ GB RAM
- 256 GB SSD
- Intel X710 or Mellanox ConnectX-5 NIC

### Kernel Requirements

- **Minimum**: Linux 4.8+ (for basic XDP support)
- **Recommended**: Linux 5.4+ (for full XDP features)
- **Optimal**: Linux 5.10+ (for advanced eBPF features)

Check your kernel version:
```bash
uname -r
```

### Network Requirements

- Internet connection for package downloads
- Static IP recommended (or DHCP reservation)
- Firewall access for container registry (docker.io, quay.io)

---

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
```

### 2. Run Bootstrap Installer

```bash
cd Scripts/autonomous/install/
sudo ./hookprobe-bootstrap.sh
```

The installer will:
1. Detect your environment (OS, architecture, kernel, NICs)
2. Install dependencies (Podman, OVS, Python packages)
3. Set up directory structure
4. Deploy systemd services
5. Run initial provisioning
6. Start monitoring agent

### 3. Verify Installation

```bash
# Check status
hookprobe-ctl status

# View logs
hookprobe-ctl logs -f

# Check health
hookprobe-ctl health
```

### 4. Enable Auto-Updates (Optional)

```bash
sudo hookprobe-ctl enable-autoupdate
```

**Done!** HookProbe is now running and monitoring your system.

---

## Installation Methods

### Method 1: Interactive Bootstrap (Recommended)

```bash
cd Scripts/autonomous/install/
sudo ./hookprobe-bootstrap.sh
```

**Features**:
- Environment detection
- Dependency installation
- Interactive confirmation
- Full validation

**Duration**: 5-15 minutes (depending on internet speed)

### Method 2: Manual Installation

For advanced users who want more control:

```bash
# 1. Install dependencies manually (Debian/Ubuntu)
sudo apt install -y podman openvswitch-switch nftables python3-pip

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Create directories
sudo mkdir -p /opt/hookprobe/{scripts,agent,xdp,config,data}
sudo mkdir -p /var/log/hookprobe
sudo mkdir -p /etc/hookprobe

# 4. Copy files
sudo cp -r Scripts/autonomous/install/* /opt/hookprobe/scripts/
sudo cp -r Scripts/autonomous/qsecbit/* /opt/hookprobe/agent/

# 5. Install systemd units
sudo cp Scripts/autonomous/install/systemd/*.service /etc/systemd/system/
sudo cp Scripts/autonomous/install/systemd/*.timer /etc/systemd/system/

# 6. Reload systemd
sudo systemctl daemon-reload

# 7. Run provision
sudo systemctl start hookprobe-provision.service

# 8. Start agent
sudo systemctl enable --now hookprobe-agent.service
```

### Method 3: Container-Based Installation (Future)

Coming soon: Pre-built container images for rapid deployment.

---

## Post-Installation

### Configuration

Edit configuration file:

```bash
sudo nano /etc/hookprobe/network-config.sh
```

**Important settings**:

```bash
# Primary network interface (auto-detected)
PRIMARY_NIC="eth0"

# XDP/eBPF DDoS mitigation (set to true to enable)
XDP_ENABLED=false

# Deployment role (server or endpoint)
DEPLOYMENT_ROLE="server"

# Qsecbit thresholds
QSECBIT_AMBER_THRESHOLD=0.45
QSECBIT_RED_THRESHOLD=0.70

# GDPR privacy settings (enabled by default)
ANONYMIZE_IP_ADDRESSES=true
ANONYMIZE_MAC_ADDRESSES=true
COLLECT_FULL_PAYLOAD=false  # NEVER enable in production (privacy violation)
```

After configuration changes:

```bash
sudo systemctl restart hookprobe-provision.service
sudo systemctl restart hookprobe-agent.service
```

### Enable XDP/eBPF DDoS Mitigation

XDP provides kernel-level packet filtering for DDoS mitigation.

**Enable XDP**:

```bash
# Edit systemd environment
sudo systemctl edit hookprobe-agent.service

# Add:
[Service]
Environment="XDP_ENABLED=true"

# Save and restart
sudo systemctl daemon-reload
sudo systemctl restart hookprobe-agent.service
```

**Verify XDP is loaded**:

```bash
# Check XDP program is attached
ip link show | grep xdp

# View XDP statistics
hookprobe-ctl metrics | grep xdp
```

**Note**: XDP mode (XDP-DRV vs XDP-SKB) is automatically selected based on NIC capabilities. See CLAUDE.md for NIC compatibility matrix.

### Firewall Configuration

If you're running a firewall, allow HookProbe ports:

**ufw (Debian/Ubuntu)**:

```bash
sudo ufw allow 8888/tcp  # Agent health check
```

### Service Management

```bash
# Start services
sudo hookprobe-ctl start

# Stop services
sudo hookprobe-ctl stop

# Restart services
sudo hookprobe-ctl restart

# Enable auto-start on boot
sudo hookprobe-ctl enable

# Disable auto-start
sudo hookprobe-ctl disable

# Check status
hookprobe-ctl status
```

### Monitoring

**View real-time logs**:

```bash
# Agent logs
hookprobe-ctl logs -f

# Provision logs
hookprobe-ctl logs hookprobe-provision.service

# All HookProbe logs
sudo journalctl -u 'hookprobe-*' -f
```

**Check health**:

```bash
hookprobe-ctl health
```

**View metrics**:

```bash
hookprobe-ctl metrics
```

**HTTP endpoints**:

```bash
# Health check
curl http://localhost:8888/health

# Metrics
curl http://localhost:8888/metrics | jq .
```

---

## Management

### Using hookprobe-ctl

The `hookprobe-ctl` command provides unified management:

```bash
# Service management
hookprobe-ctl status
hookprobe-ctl start
hookprobe-ctl stop
hookprobe-ctl restart
hookprobe-ctl enable
hookprobe-ctl disable

# Logs
hookprobe-ctl logs [-f]
hookprobe-ctl logs hookprobe-provision.service

# Updates
hookprobe-ctl update
hookprobe-ctl enable-autoupdate
hookprobe-ctl disable-autoupdate

# Monitoring
hookprobe-ctl metrics
hookprobe-ctl health

# System
hookprobe-ctl uninstall
hookprobe-ctl version
hookprobe-ctl help
```

### Manual Updates

Update HookProbe from GitHub:

```bash
sudo hookprobe-ctl update
```

This will:
1. Create backup of current installation
2. Pull latest changes from GitHub
3. Apply updates
4. Re-provision system
5. Restart services
6. Verify health
7. Rollback if anything fails

### Auto-Updates

Enable weekly auto-updates (Sundays at 3:00 AM):

```bash
sudo hookprobe-ctl enable-autoupdate
```

Disable auto-updates:

```bash
sudo hookprobe-ctl disable-autoupdate
```

Check next update time:

```bash
systemctl list-timers hookprobe-update.timer
```

### Backup and Restore

**Backups are created automatically** before each update in `/opt/hookprobe-backups/`.

**Manual backup**:

```bash
sudo tar -czf hookprobe-backup-$(date +%Y%m%d).tar.gz \
  /opt/hookprobe \
  /etc/hookprobe \
  /var/log/hookprobe
```

**Restore from backup**:

```bash
# Stop services
sudo hookprobe-ctl stop

# Restore files
sudo tar -xzf hookprobe-backup-20251123.tar.gz -C /

# Restart services
sudo hookprobe-ctl start
```

---

## Troubleshooting

### Services Won't Start

**Check status**:

```bash
hookprobe-ctl status
```

**View errors**:

```bash
journalctl -u hookprobe-agent.service --no-pager -n 50
```

**Common issues**:

1. **Missing dependencies**:
   ```bash
   sudo systemctl start hookprobe-provision.service
   ```

2. **Port conflicts**:
   ```bash
   # Check if port 8888 is in use
   sudo ss -tlnp | grep 8888
   ```

3. **Permission issues**:
   ```bash
   sudo chown -R root:root /opt/hookprobe
   sudo chmod 755 /opt/hookprobe
   ```

### Agent Health Check Fails

```bash
# Check if agent is running
systemctl is-active hookprobe-agent.service

# View logs
hookprobe-ctl logs -f

# Restart agent
sudo hookprobe-ctl restart
```

### XDP Not Loading

**Check NIC compatibility**:

```bash
# View NIC driver
ethtool -i <interface> | grep driver

# Check XDP support
cat /opt/hookprobe/config/nic.conf
```

**Supported drivers**:
- **XDP-DRV (native)**: igb, igc, i40e, ice, mlx5_core
- **XDP-SKB (generic)**: All drivers

See CLAUDE.md for complete NIC compatibility matrix.

### High Memory/CPU Usage

**Check resource usage**:

```bash
# System resources
top
htop

# HookProbe processes
ps aux | grep hookprobe
```

**Adjust resource limits**:

```bash
sudo systemctl edit hookprobe-agent.service

# Add:
[Service]
MemoryMax=1G
CPUQuota=150%
```

### Logs

**View all logs**:

```bash
sudo journalctl -u 'hookprobe-*' --since today
```

**Log files**:
- `/var/log/hookprobe/agent.log` - Agent logs
- `/var/log/hookprobe/provision.log` - Provision logs
- `/var/log/hookprobe/update.log` - Update logs
- `/var/log/hookprobe/cleanup.log` - Cleanup logs

---

## Uninstallation

### Complete Removal

```bash
sudo hookprobe-ctl uninstall
```

This will:
1. Stop all services
2. Disable systemd units
3. Remove XDP programs
4. Remove Podman containers and PODs
5. Remove OVS bridge
6. Remove firewall rules
7. Remove kernel settings
8. Remove files and directories

**⚠️ Warning**: This will **delete all data**. Backup first if needed.

### Partial Removal

**Remove services but keep files**:

```bash
sudo systemctl stop hookprobe-agent.service
sudo systemctl disable hookprobe-agent.service
```

**Remove XDP only**:

```bash
sudo ip link set dev <interface> xdpgeneric off
sudo ip link set dev <interface> xdpdrv off
```

---

## FAQ

**Q: Do I need to run the bootstrap installer on every update?**

A: No. After initial installation, use `hookprobe-ctl update` or enable auto-updates.

**Q: Can I run HookProbe in a Docker container?**

A: Not recommended. HookProbe uses OVS and XDP which conflict with Docker networking. Use bare metal or KVM/VMware VMs.

**Q: Does HookProbe require a reboot after installation?**

A: No, but recommended for kernel settings to fully apply.

**Q: Can I deploy multiple HookProbe instances?**

A: Yes, but each requires a separate physical/virtual machine. Multi-tenancy is supported in the cloud backend deployment.

**Q: How do I change the deployment role (server vs endpoint)?**

A: Edit `/etc/hookprobe/network-config.sh` and set `DEPLOYMENT_ROLE="endpoint"` or `"server"`, then restart services.

**Q: Is GDPR compliance enabled by default?**

A: Yes. IP/MAC anonymization is enabled by default. Payload collection is disabled. See GDPR.md for details.

---

## Next Steps

After installation:

1. **Configure monitoring**: Set up Grafana dashboards (see main README.md)
2. **Enable XDP**: For DDoS mitigation (see above)
3. **Configure auto-updates**: Enable weekly updates (see above)
4. **Deploy PODs**: Run the full containerized stack (see setup.sh)
5. **Review GDPR settings**: Ensure compliance (see GDPR.md)
6. **Read CLAUDE.md**: For development and advanced configuration

---

## Support

- **Documentation**: https://github.com/hookprobe/hookprobe
- **Issues**: https://github.com/hookprobe/hookprobe/issues
- **Security**: qsecbit@hookprobe.com

---

**HookProbe v5.0** - Democratizing Cybersecurity Through Edge Computing
