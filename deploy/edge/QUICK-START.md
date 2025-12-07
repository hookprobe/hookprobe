# HookProbe Quick Start Guide

**Get HookProbe running in 5 minutes!**

---

## Prerequisites

- **Debian-based Linux**: Ubuntu 22.04+, Debian 11+, Raspberry Pi OS (Bookworm)
- x86_64 or ARM64 architecture
- Root access (`sudo`)
- Internet connection

> **Note**: RHEL-based systems (Fedora, CentOS, Rocky, RHEL) are not currently supported in v5.x. We are working on nmcli-based networking for RHEL compatibility. Support coming in a future release.

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe/Scripts/autonomous/install/
```

### 2. Run Bootstrap Installer

```bash
sudo ./hookprobe-bootstrap.sh
```

Wait 5-15 minutes for installation to complete.

### 3. Verify

```bash
hookprobe-ctl status
```

You should see:
- `hookprobe-provision.service` - active
- `hookprobe-agent.service` - active

---

## Quick Commands

```bash
# Check status
hookprobe-ctl status

# View logs (live)
hookprobe-ctl logs -f

# Check health
hookprobe-ctl health

# View metrics
hookprobe-ctl metrics

# Restart services
sudo hookprobe-ctl restart

# Enable auto-updates (optional)
sudo hookprobe-ctl enable-autoupdate
```

---

## Health Check

```bash
curl http://localhost:8888/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "5.0",
  "uptime": 123
}
```

---

## Enable XDP DDoS Mitigation

```bash
# Edit service
sudo systemctl edit hookprobe-agent.service

# Add these lines:
[Service]
Environment="XDP_ENABLED=true"

# Save, then reload and restart
sudo systemctl daemon-reload
sudo systemctl restart hookprobe-agent.service

# Verify XDP is loaded
ip link show | grep xdp
```

---

## Configuration

Edit configuration:

```bash
sudo nano /etc/hookprobe/network-config.sh
```

Key settings:
- `PRIMARY_NIC` - Network interface (auto-detected)
- `XDP_ENABLED` - Enable XDP DDoS mitigation (false by default)
- `DEPLOYMENT_ROLE` - "server" or "endpoint"
- `QSECBIT_AMBER_THRESHOLD` - Amber alert threshold (0.45 default)
- `QSECBIT_RED_THRESHOLD` - Red alert threshold (0.70 default)

After changes:

```bash
sudo hookprobe-ctl restart
```

---

## Monitoring

**Logs**:
```bash
# Agent logs
hookprobe-ctl logs -f

# Provision logs
hookprobe-ctl logs hookprobe-provision.service

# All HookProbe logs
sudo journalctl -u 'hookprobe-*' -f
```

**Metrics**:
```bash
# JSON metrics
hookprobe-ctl metrics

# Or via HTTP
curl http://localhost:8888/metrics | jq .
```

---

## Updates

**Manual update**:
```bash
sudo hookprobe-ctl update
```

**Enable auto-updates** (weekly on Sundays at 3 AM):
```bash
sudo hookprobe-ctl enable-autoupdate
```

---

## Uninstall

```bash
sudo hookprobe-ctl uninstall
```

⚠️ **Warning**: This removes everything. Backup first if needed.

---

## Troubleshooting

**Services won't start**:
```bash
# Re-run provision
sudo systemctl start hookprobe-provision.service

# Check logs
journalctl -u hookprobe-agent.service --no-pager -n 50
```

**Health check fails**:
```bash
# Restart agent
sudo hookprobe-ctl restart

# Check if running
systemctl is-active hookprobe-agent.service
```

**Port conflicts**:
```bash
# Check if port 8888 is in use
sudo ss -tlnp | grep 8888
```

---

## Next Steps

1. **Deploy full POD infrastructure** (see main README.md)
2. **Configure Grafana dashboards** for monitoring
3. **Review GDPR settings** (see GDPR.md)
4. **Read CLAUDE.md** for advanced configuration

---

## Help

```bash
hookprobe-ctl help
```

**Documentation**: https://github.com/hookprobe/hookprobe
**Issues**: https://github.com/hookprobe/hookprobe/issues

---

**That's it! HookProbe is now protecting your system.**
