# HookProbe Sentinel Lite

Ultra-lightweight edge validator for constrained devices.

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel-lite/bootstrap.sh | sudo bash
```

## Features

- **No containers** - Native Python service (saves ~100MB+ RAM vs Podman)
- **Minimal RAM** - 128-384MB depending on device
- **Minimal disk** - ~50MB installed
- **Minimal bandwidth** - ~5KB bootstrap + ~8KB sentinel.py
- **Offline operation** - Works after initial install

## Target Platforms

| Device | RAM | Memory Limit |
|--------|-----|--------------|
| Raspberry Pi Zero | 512MB | 128MB |
| Raspberry Pi 3 | 1GB | 192MB |
| Raspberry Pi 3B+ | 2GB | 256MB |
| Generic ARM/IoT | 256MB+ | 128-384MB |
| LTE gateways | Varies | Auto-detected |

## Installation Options

### Option 1: Direct Download (Recommended)

```bash
# Basic install
curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel-lite/bootstrap.sh | sudo bash

# With custom MSSP endpoint
curl -sSL .../bootstrap.sh | sudo bash -s -- --mssp-endpoint my-mssp.example.com

# With custom ports
curl -sSL .../bootstrap.sh | sudo bash -s -- --port 9443 --metrics-port 9091
```

### Option 2: From Repository

```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install-sentinel-lite.sh
```

## Configuration

Configuration is stored in `/etc/hookprobe/sentinel-lite.env`:

```bash
SENTINEL_NODE_ID=sentinel-lite-myhost-a1b2c3d4
SENTINEL_REGION=us
SENTINEL_TIER=community
MSSP_ENDPOINT=mssp.hookprobe.com
MSSP_PORT=8443
SENTINEL_PORT=8443
METRICS_PORT=9090
MEMORY_LIMIT_MB=192
LOG_LEVEL=INFO
```

## Commands

```bash
# Service management
sudo systemctl start hookprobe-sentinel-lite
sudo systemctl stop hookprobe-sentinel-lite
sudo systemctl status hookprobe-sentinel-lite
sudo systemctl restart hookprobe-sentinel-lite

# View logs
sudo journalctl -u hookprobe-sentinel-lite -f

# Health check
curl http://localhost:9090/health

# Prometheus metrics
curl http://localhost:9090/metrics

# Uninstall
curl -sSL .../bootstrap.sh | sudo bash -s -- --uninstall
```

## Endpoints

| Endpoint | Port | Protocol | Description |
|----------|------|----------|-------------|
| Validation | 8443 | UDP | Edge device validation |
| Health | 9090 | HTTP | `/health` - JSON status |
| Metrics | 9090 | HTTP | `/metrics` - Prometheus format |

## Files

```
/opt/hookprobe-sentinel/
└── sentinel.py           # Main validator service

/etc/hookprobe/
└── sentinel-lite.env     # Configuration

/var/lib/hookprobe/sentinel/
└── (runtime data)

/var/log/hookprobe/
└── sentinel-lite.log     # Log file (1MB max, 2 rotations)
```

## Comparison with Full Sentinel

| Feature | Sentinel Lite | Full Sentinel |
|---------|--------------|---------------|
| Container | No (native) | Yes (Podman) |
| RAM | 128-384MB | 512MB |
| Disk | ~50MB | ~200MB |
| Dependencies | Python 3 only | Podman + Python |
| Target | Pi 3/Zero, IoT | Pi 4+, x86_64 |
| Install method | curl \| bash | ./install.sh |

## Rate Limits

| Tier | Validations/min |
|------|-----------------|
| community | 100 |
| professional | 1,000 |
| enterprise | 10,000 |

## License

MIT License - See main repository for details.
