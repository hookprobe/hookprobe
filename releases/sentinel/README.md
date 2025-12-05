# HookProbe Sentinel

     ___ ___ _  _ _____ ___ _  _ ___ _
    / __| __| \| |_   _|_ _| \| | __| |
    \__ \ _|| .` | | |  | || .` | _|| |__
    |___/___|_|\_| |_| |___|_|\_|___|____|

            "The Watchful Eye"

**Ultra-lightweight edge validator with security protection for constrained devices.**

Version: 5.0.0 | Protocol: HTP (HookProbe Transport Protocol)

---

## Features

### Core Capabilities
- **Edge Validation** - Validates HTP messages from edge devices via UDP
- **Lightweight** - 128-384MB RAM, ~50MB disk footprint
- **No Containers** - Native Python service (saves ~100MB+ vs containerized)
- **Offline Operation** - Works after initial install

### Security Protection
- **Rate Limiting** - Token bucket algorithm for DDoS protection (100 req/s default)
- **Threat Detection** - Pattern-based attack detection (SQL injection, XSS, path traversal)
- **Integrity Monitoring** - SHA256-based file change detection
- **Firewall Integration** - Automatic iptables rules via HOOKPROBE chain
- **Fail2ban** - Automatic IP banning for persistent attackers
- **Process Sandboxing** - Systemd seccomp/capabilities hardening

### QSecBit - Quantum-Safe Security
- **SHA3-256** HMAC algorithm
- **24-hour** automatic key rotation
- **Secure entropy** from /dev/urandom
- **Session management** with configurable timeouts

---

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel/bootstrap.sh | sudo bash
```

That's it! The installer will:
1. Detect your platform and available resources
2. Install dependencies (Python 3, iptables, fail2ban)
3. Download and configure Sentinel
4. Set up firewall rules and fail2ban
5. Create systemd service
6. Optionally start the service

---

## Installation Options

### Basic Install
```bash
curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel/bootstrap.sh | sudo bash
```

### Custom MSSP Endpoint
```bash
curl -sSL .../bootstrap.sh | sudo bash -s -- --mssp-endpoint security.mycompany.com
```

### Custom Ports
```bash
curl -sSL .../bootstrap.sh | sudo bash -s -- --mssp-port 9443 --health-port 8080
```

### With Authentication Token
```bash
curl -sSL .../bootstrap.sh | sudo bash -s -- --mssp-token "your-auth-token"
```

### Minimal Install (No Firewall/Fail2ban)
```bash
curl -sSL .../bootstrap.sh | sudo bash -s -- --no-firewall --no-fail2ban
```

### All Options
```
--mssp-endpoint URL   MSSP backend server (default: mssp.hookprobe.com)
--mssp-port PORT      MSSP port (default: 8443)
--mssp-token TOKEN    MSSP authentication token
--health-port PORT    Health endpoint port (default: 9090)
--region REGION       Region code (default: auto-detect)
--no-firewall         Skip firewall configuration
--no-fail2ban         Skip fail2ban configuration
--uninstall           Remove Sentinel completely
--help                Show help
```

---

## Usage

### Service Management

```bash
# Start Sentinel
sudo systemctl start hookprobe-sentinel

# Stop Sentinel
sudo systemctl stop hookprobe-sentinel

# Restart Sentinel
sudo systemctl restart hookprobe-sentinel

# Check Status
sudo systemctl status hookprobe-sentinel

# Enable on Boot (automatic)
sudo systemctl enable hookprobe-sentinel
```

### View Logs

```bash
# Live logs
sudo journalctl -u hookprobe-sentinel -f

# Last 100 lines
sudo journalctl -u hookprobe-sentinel -n 100

# Log file
tail -f /var/log/hookprobe/sentinel.log
```

### Health Check

```bash
# JSON health status
curl http://localhost:9090/health

# Example response:
{
  "status": "healthy",
  "version": "5.0.0",
  "node_id": "sentinel-myhost-a1b2c3d4",
  "region": "us",
  "tier": "community",
  "uptime": 3600,
  "validated": 1234,
  "rejected": 56,
  "blocked": 12,
  "edges": 45,
  "memory_mb": 256,
  "security": {
    "enabled": true,
    "attacks_detected": 8,
    "blocked_ips": 3,
    "integrity_ok": true
  }
}
```

### Prometheus Metrics

```bash
curl http://localhost:9090/metrics

# Available metrics:
# sentinel_validated      - Total validated messages
# sentinel_rejected       - Total rejected messages
# sentinel_errors         - Total errors
# sentinel_blocked        - Blocked by security
# sentinel_attacks_detected - Attacks detected
# sentinel_blocked_ips    - Number of blocked IPs
# sentinel_edges          - Active edge devices
# sentinel_uptime         - Uptime in seconds
# sentinel_security_enabled - Security protection status
```

---

## Connecting to MSSP

Sentinel communicates with your MSSP (Managed Security Service Provider) backend using HTP (HookProbe Transport Protocol).

### Configuration

Edit `/etc/hookprobe/sentinel.env`:

```bash
# MSSP Backend (HTP - HookProbe Transport Protocol)
MSSP_ENDPOINT=mssp.hookprobe.com
MSSP_PORT=8443
MSSP_PROTOCOL=htp
MSSP_HTP_VERSION=1.0
```

### Authentication

If your MSSP requires authentication:

```bash
# Token stored securely
/etc/hookprobe/secrets/mssp-token
```

### Network Requirements

| Direction | Port | Protocol | Description |
|-----------|------|----------|-------------|
| Outbound | 8443 | UDP/HTP | Reports to MSSP backend |
| Inbound | 8443 | UDP/HTP | Edge device validation |
| Inbound | 9090 | HTTP | Health/metrics endpoint |

### Firewall Rules (Auto-configured)

```bash
# View HOOKPROBE chain
sudo iptables -L HOOKPROBE -n -v

# Rules include:
# - Rate limiting (10 conn/s, burst 20)
# - Health port access
# - Invalid packet dropping
# - Blocked IP enforcement
```

---

## Uninstall

### Simple Command (Recommended)

```bash
sudo sentinel-uninstall
```

This will:
- Stop and disable the service
- Remove systemd service file
- Remove firewall rules (HOOKPROBE chain)
- Remove fail2ban configuration
- Remove installation files
- Preserve logs in `/var/log/hookprobe/`

### Via Bootstrap Script

```bash
curl -sSL .../bootstrap.sh | sudo bash -s -- --uninstall
```

### Manual Uninstall

```bash
# Stop service
sudo systemctl stop hookprobe-sentinel
sudo systemctl disable hookprobe-sentinel

# Remove service
sudo rm /etc/systemd/system/hookprobe-sentinel.service
sudo systemctl daemon-reload

# Remove firewall rules
sudo iptables -D INPUT -j HOOKPROBE
sudo iptables -F HOOKPROBE
sudo iptables -X HOOKPROBE

# Remove files
sudo rm -rf /opt/hookprobe/sentinel
sudo rm -f /etc/hookprobe/sentinel.env
sudo rm -rf /var/lib/hookprobe/sentinel

# Remove uninstall command
sudo rm -f /usr/local/bin/sentinel-uninstall
```

---

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_NODE_ID` | auto-generated | Unique node identifier |
| `SENTINEL_REGION` | auto-detect | Geographic region code |
| `SENTINEL_TIER` | community | Service tier (community/professional/enterprise) |
| `MSSP_ENDPOINT` | mssp.hookprobe.com | MSSP backend address |
| `MSSP_PORT` | 8443 | MSSP port |
| `HEALTH_PORT` | 9090 | Health/metrics HTTP port |
| `MEMORY_LIMIT_MB` | auto | Memory limit (128-384MB based on RAM) |
| `LOG_LEVEL` | INFO | Logging verbosity |

### Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_RATE_LIMITING` | true | Enable rate limiting |
| `RATE_LIMIT_REQUESTS` | 100 | Requests per second |
| `RATE_LIMIT_BURST` | 200 | Burst capacity |
| `ENABLE_THREAT_DETECTION` | true | Enable threat pattern detection |
| `ENABLE_INTEGRITY_CHECK` | true | Enable file integrity monitoring |
| `BLOCK_ON_ATTACK` | true | Auto-block attacking IPs |

### QSecBit Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `QSECBIT_ENABLED` | true | Enable quantum-safe features |
| `QSECBIT_HMAC_ALGO` | sha3-256 | HMAC algorithm |
| `QSECBIT_KEY_ROTATION_HOURS` | 24 | Key rotation interval |
| `QSECBIT_SESSION_TIMEOUT` | 3600 | Session timeout (seconds) |

---

## File Locations

```
/opt/hookprobe/sentinel/
├── sentinel.py              # Main validator service
└── sentinel_security.py     # Security module

/etc/hookprobe/
├── sentinel.env             # Configuration
└── secrets/
    └── mssp-token           # MSSP authentication (if configured)

/var/lib/hookprobe/sentinel/
└── signatures/
    └── basic.rules          # Threat signatures

/var/log/hookprobe/
└── sentinel.log             # Log file (1MB max, 2 rotations)

/usr/local/bin/
└── sentinel-uninstall       # Uninstall command
```

---

## Target Platforms

| Device | RAM | Auto Memory Limit |
|--------|-----|-------------------|
| Raspberry Pi Zero | 512MB | 128MB |
| Raspberry Pi 3 | 1GB | 192MB |
| Raspberry Pi 3B+ | 2GB | 256MB |
| Raspberry Pi 4 | 2-8GB | 384MB |
| Generic ARM/IoT | 256MB+ | 128-384MB |
| LTE/5G Gateways | Varies | Auto-detected |
| x86_64 Edge | 1GB+ | 384MB |

---

## Rate Limits by Tier

| Tier | Validations/min | Description |
|------|-----------------|-------------|
| community | 100 | Free tier |
| professional | 1,000 | Small business |
| enterprise | 10,000 | Large deployments |

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u hookprobe-sentinel -e

# Verify Python
python3 --version

# Check config
cat /etc/hookprobe/sentinel.env

# Test manually
sudo python3 /opt/hookprobe/sentinel/sentinel.py
```

### Cannot Connect to MSSP

```bash
# Test connectivity
ping mssp.hookprobe.com

# Check firewall
sudo iptables -L INPUT -n | grep 8443

# Verify config
grep MSSP /etc/hookprobe/sentinel.env
```

### High Memory Usage

```bash
# Check current usage
ps aux | grep sentinel

# Lower memory limit
sudo sed -i 's/MEMORY_LIMIT_MB=.*/MEMORY_LIMIT_MB=128/' /etc/hookprobe/sentinel.env
sudo systemctl restart hookprobe-sentinel
```

### Security Module Not Loading

```bash
# Check if module exists
ls -la /opt/hookprobe/sentinel/sentinel_security.py

# Test import
python3 -c "import sys; sys.path.insert(0, '/opt/hookprobe/sentinel'); from sentinel_security import SecurityManager; print('OK')"
```

---

## Security Considerations

1. **Run as root** - Required for firewall management and port binding
2. **Systemd hardening** - Service uses seccomp filters, capability restrictions
3. **File permissions** - Config files are 640, secrets are 600
4. **Network exposure** - Only health port (9090) exposed by default
5. **Log rotation** - Automatic 1MB limit with 2 backups

---

## License

MIT License - See main repository for details.

---

## Support

- **Issues**: https://github.com/hookprobe/hookprobe/issues
- **Documentation**: https://docs.hookprobe.com/sentinel
- **Community**: https://discord.gg/Cb9QyrQPkW
