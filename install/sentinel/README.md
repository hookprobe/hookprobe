# HookProbe Sentinel

> **"The Watchful Eye"** - Lightweight edge validator

## Overview

Sentinel is a lightweight validator service designed for constrained devices with limited resources. It provides essential edge node validation and health monitoring without the overhead of containers.

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 512MB | 1GB |
| Storage | 8GB | 16GB |
| Network | 1 interface | 1 interface |
| Internet | Required | Required |

## Supported Platforms

- Raspberry Pi 3 / Zero
- IoT gateways
- Low-power ARM devices
- Pico-class systems
- LTE/mobile edge devices

## Features

- Edge node validation
- Health monitoring endpoint (port 9090)
- MSSP connectivity
- Minimal footprint (~50MB)
- No container overhead
- Native Python service

## Installation

### Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/hookprobe/hookprobe/main/releases/sentinel/bootstrap.sh | sudo bash
```

### From Repository

```bash
sudo ./install.sh --tier sentinel
```

### Manual Install

```bash
cd install/sentinel
sudo ./setup.sh
```

## Configuration

Configuration is stored in `/etc/hookprobe/sentinel.conf`:

```bash
# MSSP Backend
MSSP_URL=https://your-mssp.example.com
MSSP_ID=your-mssp-id

# Health endpoint
HEALTH_PORT=9090

# Validation interval (seconds)
VALIDATION_INTERVAL=60
```

## Service Management

```bash
# Start service
sudo systemctl start hookprobe-sentinel

# Stop service
sudo systemctl stop hookprobe-sentinel

# Check status
sudo systemctl status hookprobe-sentinel

# View logs
sudo journalctl -u hookprobe-sentinel -f
```

## Health Endpoint

Check the health status:

```bash
curl http://localhost:9090/health
```

Response:
```json
{
  "status": "healthy",
  "version": "5.0.0",
  "uptime": 3600,
  "last_validation": "2024-01-01T12:00:00Z"
}
```

## Network Requirements

- **Outbound HTTPS (443)**: Required for MSSP connectivity
- **No offline mode**: Internet connectivity is mandatory

## Uninstall

```bash
sudo systemctl stop hookprobe-sentinel
sudo systemctl disable hookprobe-sentinel
sudo rm -rf /opt/hookprobe/sentinel
sudo rm /etc/systemd/system/hookprobe-sentinel.service
```

## Upgrading to Guardian

If your device gains more resources, you can upgrade to Guardian:

```bash
sudo ./install.sh --tier guardian
```

Note: Guardian requires 3GB+ RAM and 2+ network interfaces.
