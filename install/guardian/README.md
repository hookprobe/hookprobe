# HookProbe Guardian

> **"Protection on the Move"** - Portable SDN security gateway

<p align="center">
  <strong>Plug-and-Play Network Segmentation</strong><br>
  <em>MAC-Based VLAN · Multi-AP Support · Enterprise Security for $75</em>
</p>

---

## Overview

Guardian transforms Raspberry Pi 4/5 into a powerful software-defined networking (SDN) appliance. It provides enterprise-grade network segmentation, IoT isolation, and security monitoring in a portable, plug-and-play package.

**Key Capabilities:**
- **SDN/VLAN Segmentation** — Isolate IoT devices by category
- **MAC-Based Assignment** — Automatic VLAN assignment via RADIUS
- **Multi-AP Support** — Up to 4 access points with USB WiFi adapters
- **VPN Gateway** — Remote access to protected network
- **Portable Security** — Take your network security anywhere

---

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Platform | Raspberry Pi 4 (4GB) | Raspberry Pi 5 (8GB) |
| RAM | 3GB | 4-8GB |
| Storage | 16GB microSD | 32GB+ microSD (A2 rated) |
| Network | 1x WiFi + 1x Ethernet | 2x WiFi + 1x Ethernet |
| Internet | Required | Required |
| MSSP ID | Required | Required |

---

## Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| **Raspberry Pi 5** ⭐ | Recommended | Best performance, USB 3.0 |
| **Raspberry Pi 4** | Supported | Great value, proven reliable |
| Raspberry Pi 4 CM | Supported | For custom builds |
| Radxa Rock 5B | Supported | Alternative to Pi 5 |
| Orange Pi 5 | Supported | Budget alternative |
| Banana Pi M7 | Supported | 2.5GbE option |

---

## Features

### SDN & VLAN Segmentation

Guardian automatically segments your network by device type:

| VLAN | Category | Isolation | Internet |
|------|----------|-----------|----------|
| 10 | Smart Lights | Full | Cloud only |
| 20 | Thermostats | Full | Cloud only |
| 30 | Cameras | Full | Cloud only |
| 40 | Voice Assistants | Full | Cloud only |
| 50 | Appliances | Full | Cloud only |
| 60 | Entertainment | Full | Full access |
| 70 | Robots | Full | Cloud only |
| 80 | Sensors | Full | Denied |
| 999 | Quarantine | Full | Denied |

**Benefits:**
- Compromised camera can't attack your lights
- Rogue IoT device can't exfiltrate data
- Unknown devices isolated until registered
- Per-category internet policies

### Multi-AP Configuration (USB Expansion)

Extend coverage with USB WiFi adapters:

```
┌────────────────────────────────────────────────────────────────┐
│                    RASPBERRY PI 5                               │
│                                                                 │
│   Built-in       USB 3.0          USB 3.0          USB 2.0     │
│   ┌──────┐      ┌──────┐         ┌──────┐         ┌──────┐    │
│   │wlan0 │      │wlan1 │         │wlan2 │         │wlan3 │    │
│   │2.4GHz│      │5GHz  │         │5GHz  │         │2.4GHz│    │
│   │ AP   │      │Uplink│         │ AP   │         │ AP   │    │
│   └──┬───┘      └──┬───┘         └──┬───┘         └──┬───┘    │
│      │             │                │                │         │
│      ▼             ▼                ▼                ▼         │
│   Ground       Internet          1st Floor       2nd Floor    │
│   Floor        Router                                          │
└────────────────────────────────────────────────────────────────┘
```

**Recommended USB WiFi Adapters:**

| Adapter | Chipset | Band | AP Mode | Price | Notes |
|---------|---------|------|---------|-------|-------|
| **Alfa AWUS036ACM** ⭐ | MT7612U | Dual | ✅ Native | $35 | Best overall |
| **Alfa AWUS036ACHM** | MT7610U | 5GHz | ✅ Native | $30 | 5GHz only |
| **TP-Link Archer T3U Plus** | RTL8812BU | Dual | ✅ DKMS | $25 | Budget option |
| **Panda PAU09** | RT5572 | Dual | ✅ Native | $30 | Long range |
| **Alfa AWUS036ACS** | RTL8811AU | Dual | ✅ DKMS | $28 | Compact |

**Requirements for USB adapters:**
- Must support AP mode (not all adapters do!)
- Linux driver support (native or DKMS)
- 5GHz recommended for less interference
- USB 3.0 preferred for best throughput

### Maximum Configuration: 4 Access Points

With Raspberry Pi 5 and USB hub:

```bash
# Check available wireless interfaces
iw dev

# Expected output with 4 adapters:
# phy#0 → wlan0 (built-in, 2.4GHz)
# phy#1 → wlan1 (USB, 5GHz uplink)
# phy#2 → wlan2 (USB, 5GHz AP)
# phy#3 → wlan3 (USB, 2.4GHz AP)
```

**Coverage:**
- Single AP: ~1,500 sq ft
- Dual AP: ~3,000 sq ft
- Quad AP: ~6,000 sq ft

### VPN Remote Access

Access your Guardian-protected network from anywhere:

- **IKEv2 VPN** for mobile devices (iOS/Android native)
- **HTP Tunnel** for Guardian-to-Nexus communication
- **Certificate-based authentication** via LogMe2 IAM
- **Works behind NAT/CGNAT** — no port forwarding needed

### Security Stack

| Component | Purpose |
|-----------|---------|
| **Qsecbit** | AI-powered threat detection |
| **nftables** | VLAN isolation firewall |
| **hostapd** | WiFi with dynamic VLAN |
| **FreeRADIUS** | MAC-based authentication |
| **dnsmasq** | Per-VLAN DHCP/DNS |
| **Suricata** | Intrusion detection (lite) |

---

## Installation

### Quick Install (SDN Mode)

```bash
# Clone HookProbe
git clone https://github.com/hookprobe/hookprobe
cd hookprobe

# Run Guardian SDN setup
sudo ./install/guardian/scripts/setup-guardian-sdn.sh
```

### Manual Installation

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y hostapd dnsmasq bridge-utils vlan \
    freeradius python3-flask nftables

# 2. Configure hostapd with dynamic VLAN
sudo cp install/guardian/config/hostapd.conf /etc/hostapd/
sudo cp install/guardian/config/hostapd.vlan /etc/hostapd/

# 3. Configure dnsmasq for per-VLAN DHCP
sudo cp install/guardian/config/dnsmasq.conf /etc/dnsmasq.d/guardian.conf

# 4. Enable services
sudo systemctl enable hostapd dnsmasq
sudo systemctl start hostapd dnsmasq
```

### Adding USB WiFi Adapters

```bash
# 1. Plug in USB WiFi adapter
# 2. Check if detected
iw dev

# 3. Install driver if needed (for RTL8812BU)
sudo apt install -y dkms
git clone https://github.com/morrownr/88x2bu-20210702.git
cd 88x2bu-20210702
sudo ./install-driver.sh

# 4. Configure additional AP
sudo cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd-wlan2.conf
# Edit to use wlan2 interface

# 5. Start additional AP
sudo systemctl enable hostapd@wlan2
sudo systemctl start hostapd@wlan2
```

---

## Web Interface

Guardian includes a simple web UI for configuration:

**URL:** `http://192.168.1.1:8080`

### Features

- **Dashboard** — Connected devices, VLAN stats
- **Network Setup** — Scan and connect to upstream WiFi
- **Device Management** — Register and categorize devices
- **VLAN Configuration** — Create custom VLANs
- **System Status** — AP status, client count

### Screenshots

```
┌─────────────────────────────────────────────────────────────┐
│  HookProbe Guardian Setup                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  System Status                                              │
│  ┌─────────────┬─────────────┬─────────────┐              │
│  │  12         │  ● Running  │  ● Connected│              │
│  │  Clients    │   Hotspot   │   Upstream  │              │
│  └─────────────┴─────────────┴─────────────┘              │
│                                                             │
│  Connect to Upstream WiFi                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Network: [HomeWiFi              ▼]                  │   │
│  │ Password: [••••••••••           ]                   │   │
│  │ [Connect]  [Scan Networks]                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Hotspot Settings                                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SSID: [HookProbe-Guardian       ]                   │   │
│  │ Password: [••••••••••           ]                   │   │
│  │ [x] Bridge LAN port                                 │   │
│  │ [x] Bridge to upstream                              │   │
│  │ [Save Settings]                                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/hostapd/hostapd.conf` | Main AP configuration |
| `/etc/hostapd/hostapd.vlan` | VLAN-to-interface mapping |
| `/etc/hostapd/hostapd.accept` | Allowed MAC addresses |
| `/etc/dnsmasq.d/guardian.conf` | DHCP per VLAN |
| `/etc/wpa_supplicant/wpa_supplicant-wlan1.conf` | Upstream WiFi |
| `/etc/nftables.d/guardian-vlans.nft` | VLAN isolation rules |

---

## Service Management

```bash
# Core services
sudo systemctl status hostapd          # WiFi AP
sudo systemctl status dnsmasq          # DHCP/DNS
sudo systemctl status guardian-sdn     # SDN agent
sudo systemctl status guardian-webui   # Web interface

# View connected clients
iw dev wlan0 station dump

# View DHCP leases
cat /var/lib/dnsmasq/dnsmasq.leases

# View firewall rules
sudo nft list ruleset
```

---

## Network Topology

### Basic Setup (Single AP)

```
Internet ──► Router ──► Guardian (eth0)
                            │
                       wlan0 (AP)
                            │
              ┌─────────────┼─────────────┐
              │             │             │
           VLAN 10       VLAN 20       VLAN 30
           Lights       Thermo        Cameras
```

### Extended Setup (Dual AP + LAN Bridge)

```
Internet ──► Router ──► Guardian wlan1 (client mode)
                            │
              ┌─────────────┼─────────────┐
              │             │             │
           wlan0          eth0         wlan2
         (2.4GHz AP)   (LAN bridge)   (5GHz AP)
              │             │             │
         IoT devices   Wired devices  Phones/laptops
```

---

## Ports Used

| Port | Protocol | Service |
|------|----------|---------|
| 53 | UDP/TCP | DNS (dnsmasq) |
| 67 | UDP | DHCP server |
| 1812 | UDP | RADIUS authentication |
| 1813 | UDP | RADIUS accounting |
| 8080 | TCP | Guardian web UI |

---

## Troubleshooting

### WiFi AP Not Starting

```bash
# Check hostapd status
sudo systemctl status hostapd
sudo journalctl -u hostapd -n 50

# Check if interface supports AP mode
iw list | grep -A 10 "Supported interface modes"

# Common fix: unblock WiFi
sudo rfkill unblock wifi
```

### Devices Not Getting VLAN

```bash
# Check RADIUS is running
sudo systemctl status freeradius

# Test RADIUS locally
radtest testing password 127.0.0.1 0 hookprobe_radius

# Check hostapd logs for VLAN assignment
sudo journalctl -u hostapd | grep -i vlan
```

### No Internet on VLANs

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# Check NAT rules
sudo nft list table inet guardian

# Check upstream connection
ping -I wlan1 8.8.8.8
```

### USB Adapter Not Detected

```bash
# Check USB devices
lsusb

# Check kernel messages
dmesg | tail -20

# Check if driver loaded
lsmod | grep 88x2bu  # or your adapter's driver
```

---

## Upgrading to Fortress

For sites needing local monitoring dashboards:

```bash
sudo ./install.sh --tier fortress
```

**Fortress adds:**
- Local Grafana dashboards
- ClickHouse security analytics
- Full Suricata IDS
- n8n workflow automation

**Requirements:** 8GB+ RAM, 64GB+ storage

---

## Related Documentation

- **[SDN Guide](../../docs/networking/SDN.md)** — Full SDN documentation
- **[VPN Guide](../../docs/networking/VPN.md)** — Remote access setup
- **[Qsecbit](../../src/qsecbit/README.md)** — AI threat detection
- **[HTP Protocol](../../docs/architecture/hookprobe-neuro-protocol.md)** — Transport protocol

---

**HookProbe Guardian** — *Enterprise Security in Your Pocket*

Version: 5.0.0 | MIT License
