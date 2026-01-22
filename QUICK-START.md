# HookProbe Quick Start Guide

**Version 5.0.0** | Get started in 15 minutes

---

## Choose Your Deployment

HookProbe has 4 tiers. Choose based on your hardware:

| Tier | Hardware | Purpose | Install Time |
|------|----------|---------|--------------|
| **Sentinel** | LXC/VM (256MB RAM) | Lightweight validator | 5 min |
| **Guardian** | Raspberry Pi 4/5 | Portable travel hotspot | 10 min |
| **Fortress** | Mini PC (N100) | Full SDN with VLANs | 15 min |
| **Nexus** | Server (16GB+ RAM) | ML/AI compute hub | 30 min |

---

## Sentinel: Lightweight Validator

**For**: IoT gateways, LXC containers, low-power devices (256MB RAM)

### What it does
- Validates your edge node with the mesh
- Health monitoring endpoint (port 9090)
- Minimal footprint (~50MB)

### Install on LXC Container

```bash
# 1. Create LXC container (Proxmox example)
pct create 100 local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst \
  --hostname sentinel-01 \
  --memory 512 \
  --cores 1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp

# 2. Start and enter container
pct start 100
pct enter 100

# 3. Install Sentinel
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install.sh --tier sentinel
```

### Configure Mesh Connection

```bash
# Edit configuration
sudo nano /etc/hookprobe/sentinel.conf

# Set your mesh details:
MESH_URL=https://mesh.hookprobe.com
NODE_ID=your-node-id

# Restart service
sudo systemctl restart hookprobe-sentinel
```

### Verify

```bash
curl http://localhost:9090/health
# Should return: {"status": "healthy", "version": "5.0.0"}
```

---

## Guardian: Portable Travel Hotspot

**For**: Raspberry Pi 4/5 (4GB+ RAM) - portable WiFi security

### What it does
- Secure WiFi hotspot for travel
- DNS filtering and ad blocking
- IDS/IPS protection
- Connects to mesh for validation

### Hardware Needed
- Raspberry Pi 4 or 5 (4GB RAM minimum)
- MicroSD card (32GB+)
- Power supply
- Optional: USB WiFi adapter for dual-band

### Install

```bash
# 1. Flash Raspberry Pi OS Lite (64-bit) to SD card
# Use Raspberry Pi Imager: https://www.raspberrypi.com/software/

# 2. Boot Pi, connect via SSH or keyboard

# 3. Install Guardian
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install.sh --tier guardian
```

### Register with Mesh

```bash
# Get your device ID
cat /etc/hookprobe/device-id

# Configure mesh connection
sudo nano /etc/hookprobe/guardian.conf
# Add: MESH_URL=https://mesh.hookprobe.com
# Add: NODE_ID=your-node-id
# Add: VPN credentials (optional)

sudo systemctl restart hookprobe-guardian
```

### Access

| Interface | URL |
|-----------|-----|
| Web Admin | http://192.168.4.1:8080 |
| Hotspot | Connect to "HookProbe-Guardian" WiFi |

---

## Fortress: Full SDN with VLANs

**For**: Intel N100/N200 Mini PC, NUC (4GB+ RAM) - home/office security

### What it does
- Full VLAN segmentation for IoT devices
- MACsec encryption
- OpenFlow SDN controller
- Advanced monitoring with Grafana

### Hardware Needed
- Intel N100/N200 or similar Mini PC
- 4GB+ RAM
- 32GB+ SSD
- 2+ Ethernet ports (or USB adapter)

### Install

```bash
# 1. Install Debian 12 or Ubuntu 24.04 on your Mini PC

# 2. Install Fortress
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install.sh --tier fortress
```

### Configure VLANs

The installer creates default VLANs:

| VLAN | Purpose | Subnet |
|------|---------|--------|
| 10 | IoT Devices | 192.168.10.0/24 |
| 20 | Cameras | 192.168.20.0/24 |
| 30 | Guest | 192.168.30.0/24 |
| 40 | Trusted | 192.168.40.0/24 |
| 99 | Quarantine | 192.168.99.0/24 |

### Access

| Interface | URL |
|-----------|-----|
| Admin Dashboard | https://YOUR_IP:8443 |
| Grafana | http://YOUR_IP:3000 |

---

## Nexus: ML/AI Compute Hub

**For**: Servers with 16GB+ RAM, optional GPU - analytics and ML

### What it does
- GPU-accelerated threat detection
- ClickHouse analytics database
- Long-term data retention (2+ years)
- ML model training

### Hardware Needed
- Server with 16GB+ RAM
- 256GB+ NVMe SSD
- Optional: NVIDIA GPU for ML acceleration

### Install

```bash
# 1. Install Debian 12 or Ubuntu 24.04

# 2. Install Nexus
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install.sh --tier nexus

# 3. Optional: Enable GPU
sudo ./install.sh --enable-gpu
```

---

## How Tiers Connect

```
        ┌─────────────────────────────────────────────┐
        │              HTP Mesh Protocol              │
        │           (Trust Fabric + Qsecbit)          │
        └─────────────────────┬───────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Guardian    │    │   Fortress    │    │    Nexus      │
│ (Travel WiFi) │    │ (Home SDN)    │    │ (ML/AI Hub)   │
└───────┬───────┘    └───────┬───────┘    └───────────────┘
        │                    │
        ▼                    ▼
┌───────────────┐    ┌───────────────┐
│   Sentinel    │    │   Sentinel    │
│  (Validator)  │    │  (Validator)  │
└───────────────┘    └───────────────┘
```

---

## Validation Flow

1. **Sentinel** connects to mesh with `NODE_ID`
2. **Guardian/Fortress** register their `device-id` with mesh
3. **Mesh** validates devices and issues certificates
4. **VPN** access enabled after validation

### Check Validation Status

```bash
# On any edge device
hookprobe-ctl status

# Expected output:
# Status: VALIDATED
# Mesh: connected
# Last sync: 2025-12-07 10:30:00
```

---

## Common Commands

```bash
# Check service status
sudo systemctl status hookprobe-*

# View logs
sudo journalctl -u hookprobe-guardian -f

# Restart services
sudo systemctl restart hookprobe-guardian

# Check mesh connection
hookprobe-ctl mesh status

# Update to latest version
cd hookprobe && git pull && sudo ./install.sh --upgrade
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Can't reach mesh | Check firewall, ensure UDP 4719 (HTP) is open |
| Validation failed | Verify NODE_ID and MESH_URL in config |
| Service won't start | Check logs: `journalctl -u hookprobe-* -n 50` |
| No internet on hotspot | Check upstream connection on Guardian |

---

## Next Steps

- **[Full Documentation](docs/DOCUMENTATION-INDEX.md)** - Complete guides
- **[Architecture Guide](ARCHITECTURE.md)** - Understand the system
- **[VPN Setup](docs/networking/VPN.md)** - Remote access
- **[SDN Guide](docs/networking/SDN.md)** - VLAN segmentation (Fortress)

---

**Need Help?** Open an issue at https://github.com/hookprobe/hookprobe/issues
