# HookProbe Quick Start Guide

## 🚀 Installation in 3 Steps

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

The interactive installer will:

1. **Detect Network Interfaces** - Automatically scans your hardware
2. **Configure Networks** - Set IP addresses, bridges, VNIs, and VXLANs
3. **Generate Security** - Create secure passwords and encryption keys
4. **Deploy PODs** - Install and configure all 7 security PODs

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

## 📚 Next Steps

1. **Review Security Settings** - Check [SECURITY.md](docs/SECURITY.md)
2. **Configure Grafana Dashboards** - Import security templates
3. **Set Up Alerts** - Configure Grafana alerting
4. **Enable Cloudflare Tunnel** - For remote access (optional)
5. **Review GDPR Settings** - See [GDPR.md](docs/GDPR.md)

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
