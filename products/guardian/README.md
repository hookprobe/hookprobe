# HookProbe Guardian

> **"Protection on the Move"** - Portable security gateway for travelers

<p align="center">
  <strong>Liberty Cybersecurity for the Masses</strong><br>
  <em>Enterprise Security at $75 · L2-L7 Threat Detection · Travel Companion</em>
</p>

---

## Overview

Guardian transforms Raspberry Pi 4/5 into a portable security gateway. Perfect for securing your devices on hotel WiFi, coffee shops, airports, and any untrusted network. Guardian creates a secure WiFi hotspot that protects all your connected devices.

**Version 5.0.0 Liberty** — Affordable cybersecurity for everyone.

**Key Capabilities:**
- **Secure WiFi Hotspot** — Create your own protected network anywhere
- **L2-L7 Threat Detection** — Full OSI stack threat monitoring
- **Mobile Network Protection** — Hotel/public WiFi security
- **IDS/IPS Protection** — Suricata-based intrusion detection
- **DNS Filtering** — Block malicious domains with AdGuard
- **Connected Devices** — Track all devices on your network
- **Web Dashboard** — Monitor threats and manage devices
- **Portable Security** — Take your network security anywhere

---

## Guardian vs Fortress

Guardian is designed for **simplicity and portability**. For advanced features like VLAN segmentation, use **Fortress**.

| Feature | Guardian | Fortress |
|---------|----------|----------|
| **Use Case** | Travel, portable, simple | Home/Office, permanent, advanced |
| **Network** | Single network (br0) | Multi-VLAN segmentation |
| **WiFi Mode** | Simple AP hotspot | Multi-VAP with RADIUS VLANs |
| **Device Isolation** | Firewall rules | VLAN per device category |
| **WiFi Adapters** | Any USB adapter with AP mode | VAP-capable adapters required |
| **Network Cards** | USB WiFi | PCIe NICs, enterprise adapters |
| **SDN/OpenFlow** | Not included | Full OVS integration |
| **Setup Time** | 5 minutes | 30+ minutes |
| **Complexity** | Simple | Advanced |

### Want More Customization?

If you need:
- **VLAN segmentation** for IoT device isolation
- **OpenFlow SDN** with Open vSwitch
- **Multi-VAP WiFi** with per-device VLAN assignment
- **PCIe network cards** for better performance
- **Enterprise-grade networking**

**→ Use [HookProbe Fortress](../fortress/) instead.**

Fortress supports:
- **PCIe WiFi cards** (Intel AX200/210, Qualcomm) for better performance
- **PCIe NICs** (Intel i225/i226, Mellanox) for 2.5GbE/10GbE
- **VAP-capable USB adapters** (Atheros AR9271, MediaTek MT7612U)
- **Full VLAN segmentation** with FreeRADIUS dynamic assignment
- **OpenFlow SDN** for advanced traffic control

---

## Liberty Mission

**"Cybersecurity for the Masses"**

Guardian democratizes enterprise security:
- **$75 hardware cost** (Raspberry Pi 4/5)
- **Zero licensing fees** (MIT License)
- **Full security stack** comparable to $10,000+ commercial appliances
- **Open source** — audit, modify, contribute

---

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Platform | Raspberry Pi 4 (4GB) | Raspberry Pi 5 (8GB) |
| RAM | 3GB | 4-8GB |
| Storage | 16GB microSD | 32GB+ microSD (A2 rated) |
| Network | 1x WiFi (built-in) + 1x USB WiFi | 2x WiFi interfaces |
| Internet | Required | Required |

### WiFi Adapter Recommendations

**For Guardian (Any AP-capable adapter works):**
- Built-in WiFi (wlan0) for uplink to hotel/airport WiFi
- USB WiFi (wlan1) for your secure hotspot
- Examples: TP-Link TL-WN722N, Panda PAU09, Alfa AWUS036ACH

**For Fortress (VAP-capable adapters required):**
- **Atheros AR9271** — Best open-source driver support, multiple VAPs
- **MediaTek MT7612U** — 5GHz support, good for multi-VLAN
- **PCIe cards** — Intel AX200/210 for best performance

---

## Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| **Raspberry Pi 5** ⭐ | Recommended | Best performance, USB 3.0 |
| **Raspberry Pi 4** | Supported | Great value, proven reliable |
| **Intel N100** | Supported | Mini PC option, PCIe slots |
| Raspberry Pi 4 CM | Supported | For custom builds |
| Radxa Rock 5B | Supported | Alternative to Pi 5 |
| Orange Pi 5 | Supported | Budget alternative |

---

## Features

### Secure WiFi Hotspot

Guardian creates a protected WiFi network for your devices:

```
┌─────────────────────────────────────────────────────────────────┐
│                    GUARDIAN TRAVEL SETUP                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Hotel/Airport WiFi ──► wlan0 (Uplink) ──► Guardian            │
│                                              │                   │
│                                              ▼                   │
│                                        ┌──────────┐             │
│                                        │ Security │             │
│                                        │  Stack   │             │
│                                        │ IDS/IPS  │             │
│                                        │   WAF    │             │
│                                        │   DNS    │             │
│                                        └──────────┘             │
│                                              │                   │
│   Your Devices ◄────── wlan1 (Hotspot) ◄────┘                   │
│   - Laptop             "HookProbe-Guardian"                      │
│   - Phone              192.168.4.0/24                           │
│   - Tablet             All on same network                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Features:**
- WPA2 encrypted hotspot
- NAT isolation from untrusted network
- All traffic scanned by IDS/IPS
- DNS filtering blocks malicious domains
- Web dashboard at http://192.168.4.1:8080

### L2-L7 Threat Detection

Guardian monitors threats across all OSI layers:

| Layer | Detection Types | Examples |
|-------|----------------|----------|
| **L2 Data Link** | ARP Spoofing, MAC Flooding, Evil Twin, Rogue DHCP | Man-in-the-Middle via ARP cache poisoning |
| **L3 Network** | IP Spoofing, ICMP Attacks, Routing Attacks | Ping of Death, IP source spoofing |
| **L4 Transport** | Port Scans, SYN Flood, TCP Anomalies, UDP Flood | Network reconnaissance, DDoS attacks |
| **L5 Session** | SSL Attacks, Session Hijacking, Auth Bypass | SSL stripping, credential stuffing |
| **L6 Presentation** | Encoding Attacks, Format Exploits | XXE, weak cipher exploitation |
| **L7 Application** | Web Attacks (SQLi, XSS), DNS Threats, Malware C2 | SQL injection, DNS tunneling |

### Mobile Network Protection

Specialized protection for hotel WiFi, airports, and public networks:

- **Captive Portal Detection** — Safe handling of login portals
- **Evil Twin Detection** — Identifies rogue access points
- **SSL/TLS Interception Detection** — Alerts on HTTPS interception
- **DNS Security Verification** — Detects DNS hijacking
- **Network Trust Classification** — TRUSTED, VERIFIED, UNKNOWN, SUSPICIOUS, HOSTILE
- **VPN Recommendations** — Automatic VPN suggestions based on trust level

### Connected Devices Tracking

Guardian tracks all devices connected to your hotspot:

- **MAC Address Tracking** — See all connected devices
- **Device Names** — Identify devices by hostname
- **Connection Status** — Real-time connection monitoring
- **Web UI Dashboard** — View all devices at http://192.168.4.1:8080

### Security Stack

| Component | Purpose |
|-----------|---------|
| **Layer Threat Detector** | L2-L7 OSI threat detection |
| **Mobile Protection** | Hotel/public WiFi security |
| **QSecBit** | AI-powered threat scoring |
| **Suricata IDS/IPS** | Network intrusion detection & prevention |
| **Zeek** | Network traffic analysis & logging |
| **ModSecurity WAF** | Web application firewall |
| **XDP/eBPF** | Kernel-level DDoS protection |
| **Threat Aggregator** | Correlates alerts from all security tools |
| **nftables** | Firewall rules |
| **hostapd** | WiFi access point |
| **FreeRADIUS** | MAC authentication & tracking |
| **dnsmasq** | DHCP/DNS server |
| **AdGuard DNS** | Ad blocking & DNS privacy |

### HTP Secure Communication

Guardian connects to the MSSP cloud for threat intelligence:

- **HTP Protocol** — Secure UDP transport (port 4719)
- **ChaCha20-Poly1305** — Authenticated encryption
- **NAT/CGNAT Traversal** — Works behind any firewall
- **Automatic Reconnection** — Resilient connection

---

## Installation

### Quick Install

```bash
# Clone HookProbe
git clone https://github.com/hookprobe/hookprobe
cd hookprobe

# Run Guardian setup
sudo ./products/guardian/scripts/setup.sh

# Or use the main installer
sudo ./install.sh --tier guardian
```

**What gets installed:**
- L1-L7 OSI Layer Threat Detection
- QSecBit AI-Powered Security Scoring
- Suricata IDS/IPS
- ModSecurity WAF
- XDP/eBPF DDoS Protection
- MAC Authentication & Device Tracking
- HTP Secure Communication
- Web Dashboard

### After Installation

1. **Connect to your Guardian hotspot:**
   - SSID: `HookProbe-Guardian` (or your custom name)
   - Password: Set during installation

2. **Access the Web Dashboard:**
   - URL: `http://192.168.4.1:8080`

3. **Configure upstream WiFi:**
   - Go to WiFi tab in dashboard
   - Scan for networks
   - Connect to hotel/airport WiFi

---

## Web Interface

**URL:** `http://192.168.4.1:8080`

### Dashboard Tab
- Security Overview — RAG status for threats
- Network Status — WAN/LAN interface status
- Connected Clients — Number of devices
- Security Services — Container status

### Security Tab
- Mobile Network Protection — Trust level, protection score
- L2-L7 Layer Threats — OSI layer breakdown
- Suricata Alerts — Real-time IDS alerts
- XDP Protection — DDoS mitigation stats

### Devices Tab
- Connected Devices — All devices on your network
- MAC Addresses — Device identification
- IP Assignments — DHCP leases

### WiFi Tab
- Hotspot Settings — Configure SSID/password
- Upstream WiFi — Connect to internet source
- Interface Status — Network interface details

### System Tab
- System Information — Uptime, memory, disk
- Service Management — Start/stop services
- System Actions — Restart, reboot

---

## Configuration

Guardian uses a simple configuration file:

```bash
sudo nano /etc/guardian/guardian.yaml
```

**Key sections:**
- `radius:` — MAC authentication settings
- `network:` — Network configuration (192.168.4.0/24)
- `htp:` — MSSP connection settings
- `security:` — Threat detection thresholds
- `webui:` — Web interface settings

---

## Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GUARDIAN SIMPLE ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Internet ──► Hotel WiFi ──► wlan0 (WAN/Uplink)                │
│                                    │                             │
│                                    ▼                             │
│                              ┌──────────┐                        │
│                              │ Guardian │                        │
│                              │   br0    │                        │
│                              │192.168.4.1                        │
│                              └────┬─────┘                        │
│                                   │                              │
│                              wlan1 (LAN/Hotspot)                 │
│                              "HookProbe-Guardian"                │
│                                   │                              │
│                    ┌──────────────┼──────────────┐              │
│                    │              │              │              │
│                 Laptop         Phone         Tablet             │
│              192.168.4.101  192.168.4.102  192.168.4.103        │
│                                                                  │
│              All devices on same network (192.168.4.0/24)       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**For VLAN segmentation (device isolation by category), use Fortress.**

---

## Service Management

```bash
# Core services
sudo systemctl status hostapd          # WiFi AP
sudo systemctl status dnsmasq          # DHCP/DNS
sudo systemctl status freeradius       # MAC tracking
sudo systemctl status guardian-webui   # Web interface

# Security services
sudo systemctl status guardian-suricata     # IDS/IPS
sudo systemctl status guardian-zeek         # Network analysis
sudo systemctl status guardian-waf          # Web firewall
sudo systemctl status guardian-xdp          # DDoS protection
sudo systemctl status guardian-aggregator   # Threat correlation

# View connected clients
iw dev wlan1 station dump

# View DHCP leases
cat /var/lib/misc/dnsmasq.leases
```

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

### No Internet Access

```bash
# Check upstream connection
ping -c 3 8.8.8.8

# Check NAT rules
sudo nft list ruleset | grep masquerade

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1
```

### Devices Not Connecting

```bash
# Check DHCP is running
sudo systemctl status dnsmasq

# View DHCP leases
cat /var/lib/misc/dnsmasq.leases

# Check bridge
ip addr show br0
```

---

## Upgrading to Fortress

If you need advanced features, consider upgrading to Fortress:

### When to Upgrade

- You have **IoT devices** that need isolation (cameras, smart home)
- You want **VLAN segmentation** per device category
- You need **OpenFlow SDN** for traffic control
- You have **PCIe slots** for better network cards
- You want **enterprise-grade networking**

### Hardware for Fortress

**Recommended Network Cards:**

| Type | Model | Speed | Notes |
|------|-------|-------|-------|
| **PCIe WiFi** | Intel AX210 | WiFi 6E | Best performance |
| **PCIe NIC** | Intel i225-V | 2.5GbE | Multi-port options |
| **PCIe NIC** | Mellanox ConnectX-3 | 10GbE | Enterprise grade |
| **USB WiFi** | Atheros AR9271 | 2.4GHz | VAP-capable, open driver |
| **USB WiFi** | MediaTek MT7612U | Dual-band | VAP-capable |

**Recommended Platforms:**

| Platform | PCIe Slots | Notes |
|----------|------------|-------|
| Intel N100 Mini PC | 1x PCIe | Great value |
| Radxa Rock 5B | 1x PCIe | ARM alternative |
| Mini-ITX Build | 2-4x PCIe | Maximum flexibility |

See [Fortress documentation](../fortress/) for full setup guide.

---

## Version History

| Version | Codename | Features |
|---------|----------|----------|
| 5.0.0 | **Liberty** | Simple mode, L2-L7 detection, mobile protection |
| 4.0.0 | Sentinel | Basic IDS, Suricata integration |
| 3.0.0 | Pioneer | Multi-AP support |

---

**HookProbe Guardian** — *Liberty Cybersecurity for the Masses*

Version: 5.0.0 Liberty | MIT License
