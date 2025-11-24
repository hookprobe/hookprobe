# HookProbe Quick Start Guide

## 🚀 Installation in 3 Steps (NEW Simplified Process!)

HookProbe v5.0 introduces an **interactive installation wizard** that eliminates manual configuration. Just run one command and answer a few prompts!

### Step 1: Clone Repository

```bash
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
```

### Step 2: Run Interactive Installer

```bash
sudo ./install.sh
```

### Step 3: Follow the Wizard

The interactive installer will automatically:

1. **Detect Network Interfaces** - Scans your hardware (eth0, wlan0, etc.)
2. **Configure Networks** - Prompts for IP addresses, automatically sets up bridges, VNIs, and VXLANs
3. **Generate Security** - Creates secure passwords and encryption keys (no manual editing!)
4. **Deploy PODs** - Installs and configures all 7 security PODs
5. **Verify Deployment** - Runs health checks

**⏱️ Installation completes in 15-20 minutes!**

---

## ✨ What's New in v5.0

### Simplified Installation Process

**Before v5.0** (Manual):
```bash
# Old process - manual editing required
git clone repo
nano config.sh          # Manual editing
  - Set HOST_IP
  - Set passwords
  - Set PSK keys
  - Configure VXLANs
sudo ./setup.sh
```

**v5.0** (Automated):
```bash
# New process - fully interactive
git clone repo
sudo ./install.sh       # Interactive wizard does everything!
  ✓ Detects interfaces automatically
  ✓ Prompts for IP (with validation)
  ✓ Generates passwords securely
  ✓ Creates encryption keys
  ✓ Configures all PODs
  ✓ Deploys containers
```

**Benefits:**
- ✅ **No manual file editing** - wizard handles everything
- ✅ **Automatic network detection** - finds interfaces for you
- ✅ **Secure by default** - generates cryptographically secure passwords
- ✅ **Error validation** - validates inputs before proceeding
- ✅ **Guided process** - clear prompts and explanations
- ✅ **Professional configuration** - production-ready settings

## 📋 Configuration Menu

When you run `./install.sh`, you'll see:

```
HookProbe Installer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Main Deployments:
  1) Edge Deployment (SBC/Intel N100/Raspberry Pi)
  2) Cloud Backend (MSSP Multi-Tenant)

Configuration:
  c) Run Configuration Wizard

Optional Add-ons:
  3) Install n8n Workflow Automation (POD 008)
  4) Install LTE/5G Connectivity
  5) Install ClickHouse Analytics

Maintenance:
  6) Uninstall HookProbe
  7) Update Containers

  q) Quit
```

## 🎯 Deployment Options

### Edge Deployment (Home/Office)

```bash
sudo ./install.sh
# Select option 1
# Follow configuration wizard
# Installation completes in 15-20 minutes
```

**Minimum Requirements:**
- Intel N100 or equivalent
- 16GB RAM
- 500GB SSD
- 1Gbps NIC

### Cloud Backend (MSSP)

```bash
sudo ./install.sh
# Select option 2
# Configure multi-tenant settings
# Deployment completes in 30-40 minutes
```

**Minimum Requirements:**
- Intel Xeon / AMD EPYC
- 32GB RAM
- 1TB NVMe SSD
- 10Gbps NIC

## 🔧 Configuration Wizard Details

The wizard automatically configures:

### Network Settings
- WAN interface selection
- Host IP address
- Bridge configuration
- POD network ranges
- VNI numbers for VXLAN

### Security
- VXLAN PSK encryption keys
- Grafana admin password
- PostgreSQL credentials
- Redis authentication
- Keycloak admin access

### Features
- Cloudflare Tunnel (optional)
- XDP/eBPF DDoS protection
- GDPR compliance settings

## 📊 After Installation

### Access Services

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| **Grafana** | http://YOUR_IP:3000 | admin / [configured] |
| **Logto Admin** | http://YOUR_IP:3002 | admin / [configured] |
| **Qsecbit API** | http://YOUR_IP:8888 | - |

⚠️ **Important:** Passwords are configured during installation wizard. Note them down securely!

### Verify Installation

```bash
# Check POD status
sudo podman ps

# Check logs
sudo journalctl -u hookprobe-agent -f

# Test Grafana
curl -I http://localhost:3000

# View configuration
cat install/edge/config.sh  # (protected file, root only)
```

## 🔄 Adding Features Later

### Install n8n Workflow Automation

```bash
sudo ./install.sh
# Select option 3
# Follow configuration for POD 008
```

### Update Containers

```bash
sudo ./install.sh
# Select option 7
# Updates all container images
```

## 🧪 CI/CD & Quality Assurance

HookProbe v5.0 includes comprehensive CI/CD testing to ensure reliable deployments:

### Automated Testing

Every commit is automatically tested:

- ✅ **Installation Tests** - Validates installer and configuration wizard
- ✅ **Container Tests** - Verifies Podman, OVS, and networking
- ✅ **Python Linting** - Ensures code quality (flake8, pylint, bandit)
- ✅ **ShellCheck** - Validates shell scripts
- ✅ **Link Validation** - Checks documentation links

### CI/CD Status Badges

Check the build status on the README:

[![Installation Tests](https://github.com/hookprobe/hookprobe/actions/workflows/installation-test.yml/badge.svg)](https://github.com/hookprobe/hookprobe/actions/workflows/installation-test.yml)
[![Container Tests](https://github.com/hookprobe/hookprobe/actions/workflows/container-tests.yml/badge.svg)](https://github.com/hookprobe/hookprobe/actions/workflows/container-tests.yml)

### Running Tests Locally

Before deploying, you can run tests locally:

```bash
# Syntax validation
bash -n install.sh
find install/ -name "*.sh" -exec bash -n {} \;

# Test configuration wizard
sudo ./install.sh
# Select option 'c' for configuration

# Verify Podman and OVS
podman --version
sudo ovs-vsctl --version
```

### Complete CI/CD Documentation

See [docs/CI-CD.md](docs/CI-CD.md) for:
- Complete testing strategy
- Contributing guidelines
- Troubleshooting CI/CD issues
- Local test commands

---

## 📚 Next Steps

1. **Review Security Settings** - Check [SECURITY.md](docs/SECURITY.md)
2. **Configure Grafana Dashboards** - Import security templates
3. **Set Up Alerts** - Configure Grafana alerting
4. **Enable Cloudflare Tunnel** - For remote access (optional)
5. **Review GDPR Settings** - See [GDPR.md](docs/GDPR.md)
6. **Check CI/CD Status** - Review automated test results

## 🆘 Troubleshooting

### Configuration Not Saved

```bash
# Re-run configuration wizard
sudo ./install.sh
# Select option 'c'
```

### Network Interface Not Detected

```bash
# Check interfaces manually
ip link show

# Verify drivers loaded
lsmod | grep -E "igb|igc|i40e"
```

### Deployment Failed

```bash
# Check logs
sudo journalctl -u hookprobe-agent -n 100

# Review installation log
cat /var/log/hookprobe-install.log
```

## 📖 Full Documentation

- [Complete Installation Guide](docs/installation/INSTALLATION.md)
- [Edge Deployment Checklist](install/edge/checklist.md)
- [Cloud Deployment Guide](docs/installation/cloud-deployment.md)
- [Architecture Overview](docs/architecture/security-model.md)

## 💡 Key Advantages

✅ **No Manual Configuration** - Wizard handles everything
✅ **Auto-Detection** - Finds network interfaces automatically
✅ **Secure by Default** - Generates random passwords
✅ **Single Command** - `./install.sh` does it all
✅ **Guided Process** - Step-by-step prompts
✅ **Professional** - Production-ready configuration

---

**Need Help?** See [CONTRIBUTING.md](docs/CONTRIBUTING.md) or open an issue.
