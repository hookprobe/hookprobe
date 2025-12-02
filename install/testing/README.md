# HookProbe Lightweight Testing/Development Setup

This directory contains scripts for setting up a lightweight HookProbe instance optimized for:
- **Development and testing**
- **Learning and experimentation**
- **Resource-constrained devices** (Raspberry Pi 4B, 4-8GB RAM)

## Quick Start

### Raspberry Pi 4B (4GB RAM)

```bash
# 1. Clone the repository
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe

# 2. Run lightweight setup (as root or with sudo)
sudo ./install/testing/lightweight-setup.sh

# 3. Start the testing environment
sudo /opt/hookprobe/testing/start-testing.sh
```

## What Gets Installed

The lightweight setup installs a minimal HookProbe stack:

| Component | Purpose | Memory |
|-----------|---------|--------|
| **PostgreSQL 16** | Database | ~100MB |
| **VictoriaMetrics** | Time-series metrics | ~50MB |
| **Grafana** | Dashboards & visualization | ~100MB |

**Total estimated memory usage**: ~250MB (leaves plenty of RAM for development)

## System Requirements

### Minimum
- **RAM**: 2GB (4GB+ recommended)
- **Disk**: 10GB free space
- **OS**: Debian 12+, Ubuntu 22.04+, RHEL 9+, Fedora 40+
- **Architecture**: ARM64 (aarch64) or x86_64

### Supported Devices
- ✅ Raspberry Pi 4B (4GB/8GB) - **Primary target**
- ✅ Raspberry Pi 5 (4GB/8GB)
- ✅ Any x86_64 Linux PC/VM with 4GB+ RAM
- ✅ Rock Pi 4, Orange Pi 5, ODROID N2+
- ❌ Raspberry Pi 3 (ARMv7 32-bit not supported)

## Installation Steps

The setup script automatically:

1. **Detects platform** - OS, architecture, available resources
2. **Checks system resources** - Ensures minimum RAM/disk requirements
3. **Installs container runtime** - Podman (preferred) or Docker
4. **Installs required tools** - Python 3, pip, git, curl
5. **Configures container runtime** - Enables rootless mode if possible
6. **Creates persistent volumes** - For database and metrics storage
7. **Pulls container images** - Minimal set (PostgreSQL, Grafana, VictoriaMetrics)
8. **Creates network** - Isolated container network
9. **Generates configuration** - Secure passwords and environment variables
10. **Creates management scripts** - Start/stop scripts for easy management

## Usage

### Start Testing Environment

```bash
sudo /opt/hookprobe/testing/start-testing.sh
```

This starts:
- **PostgreSQL**: Database (internal only)
- **VictoriaMetrics**: http://localhost:8428
- **Grafana**: http://localhost:3000 (admin/admin)

### Stop Testing Environment

```bash
sudo /opt/hookprobe/testing/stop-testing.sh
```

This stops and removes all containers (data is preserved in volumes).

### Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | admin / admin |
| **VictoriaMetrics** | http://localhost:8428 | - |
| **PostgreSQL** | localhost:5432 | hookprobe / (see config) |

## Configuration

Configuration files are stored in `/opt/hookprobe/testing/`:

- `env` - Environment variables (passwords, database URLs)
- `start-testing.sh` - Start script
- `stop-testing.sh` - Stop script

### Custom Configuration

You can customize the installation by setting environment variables before running the setup:

```bash
# Custom volume names
export VOLUME_POSTGRES_DATA="my-postgres-data"
export VOLUME_GRAFANA_DATA="my-grafana-data"

# Custom ports
export PORT_HTTP=8080
export PORT_GRAFANA=3001

# Run setup
sudo -E ./install/testing/lightweight-setup.sh
```

## Troubleshooting

### Error: "VOLUME_POSTGRES_DATA: unbound variable"

This error occurs when the setup script tries to use a variable that hasn't been defined. The fixed lightweight-setup.sh script now:
- Defines all variables with default values using `${VAR:-default}` syntax
- Is compatible with `set -u` (exit on undefined variable)

### Low Memory Warning

If you have less than 4GB RAM, some services may be disabled automatically:

```
⚠ WARNING: Low RAM (2GB). Some services will be disabled.
```

The minimal mode installs only:
- PostgreSQL (required)
- VictoriaMetrics (lightweight metrics)
- Grafana (monitoring)

### Container Runtime Issues

**Podman vs Docker:**
- Script prefers Podman (more secure, rootless mode)
- Falls back to Docker if Podman not available
- Both work identically for testing

**Permission Denied:**
```bash
# If running as non-root user, add to docker/podman group
sudo usermod -aG docker $USER  # Docker
sudo usermod -aG podman $USER  # Podman

# Logout and login again
```

### Port Conflicts

If ports 3000 or 8428 are already in use:

```bash
# Check what's using the port
sudo ss -tulpn | grep :3000

# Kill the process or use custom ports
export PORT_GRAFANA=3001
sudo -E ./install/testing/lightweight-setup.sh
```

## Differences from Production Setup

This lightweight testing setup differs from production (`install/edge/setup.sh`):

| Feature | Testing | Production |
|---------|---------|------------|
| **Memory usage** | ~250MB | ~2-4GB |
| **Services** | 3 core services | 15+ services |
| **Security** | Development mode | Hardened (SELinux, AppArmor) |
| **Networking** | Simple bridge | OVS, VXLANs, segmentation |
| **IDS/IPS** | Disabled | Suricata, Snort3 |
| **Honeypots** | Disabled | Multiple honeypots |
| **MSSP** | Disabled | Full MSSP platform |

**⚠ DO NOT use testing setup in production!**

## Next Steps

After installation, you can:

1. **Explore the platform**
   - Access Grafana dashboards
   - Review container logs: `podman logs hookprobe-postgres-test`
   - Connect to database: `psql -h localhost -U hookprobe -d hookprobe`

2. **Develop and test**
   - Modify source code in `src/`
   - Test changes in containerized environment
   - Use volume mounts for live code updates

3. **Upgrade to full installation**
   - When ready for production, run `install/edge/setup.sh`
   - Migrates data from testing volumes
   - Enables all security features

## Contributing

Found a bug or want to improve the testing setup?

1. Fork the repository
2. Create a feature branch: `git checkout -b fix/testing-setup`
3. Make your changes
4. Test on Raspberry Pi 4B if possible
5. Submit a pull request

## Support

- **Documentation**: https://github.com/hookprobe/hookprobe/wiki
- **Issues**: https://github.com/hookprobe/hookprobe/issues
- **Discussions**: https://github.com/hookprobe/hookprobe/discussions

## License

HookProbe is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.
