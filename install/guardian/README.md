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
- **HTP Protocol** — Secure transport to MSSP cloud (mssp.hookprobe.com)
- **Web Dashboard** — Monitor threats and manage devices
- **Portable Security** — Take your network security anywhere

> **Note:** For advanced VLAN segmentation and SDN features, see [HookProbe Fortress](../fortress/). Guardian focuses on simplicity and portability.

---

## Guardian vs Fortress

| Feature | Guardian | Fortress |
|---------|----------|----------|
| **Use Case** | Travel, portable | Home/Office, permanent |
| **WiFi Mode** | Single AP hotspot | Multi-VLAN with RADIUS |
| **Network** | Simple NAT | SDN/OpenFlow |
| **Device Isolation** | Firewall rules | VLAN segmentation |
| **WiFi Adapters** | Any USB adapter | Atheros AR9271, MT7612U* |
| **Setup** | 5 minutes | 30 minutes |
| **Complexity** | Simple | Advanced |

\* *VLAN-capable adapters required for dynamic VLAN assignment*

---

## Liberty Mission

**"Cybersecurity for the Masses"**

Guardian democratizes enterprise security:
- **$75 hardware cost** (Raspberry Pi 4/5)
- **Zero licensing fees** (MIT License)
- **Full feature parity** with $10,000+ commercial appliances
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

**For Guardian (Simple Hotspot):**
- Any USB WiFi adapter with AP mode support
- Built-in WiFi (wlan0) for uplink, USB WiFi (wlan1) for hotspot
- Examples: TP-Link TL-WN722N, Panda PAU09, Alfa AWUS036ACH

**For Fortress (VLAN Segmentation):**
- Requires adapters supporting multiple VAPs (Virtual Access Points)
- **Atheros AR9271** — Best compatibility, open source driver
- **MediaTek MT7612U** — 5GHz support, good performance
- **Ralink RT5572** — Dual-band, reliable

---

## Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| **Raspberry Pi 5** ⭐ | Recommended | Best performance, USB 3.0 |
| **Raspberry Pi 4** | Supported | Great value, proven reliable |
| **Intel N100** | Supported | Mini PC option, 2.5GbE |
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
│   - Tablet                                                       │
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
| **L2 Data Link** | ARP Spoofing, MAC Flooding, Evil Twin, VLAN Hopping, Rogue DHCP | Man-in-the-Middle via ARP cache poisoning |
| **L3 Network** | IP Spoofing, ICMP Attacks, Routing Attacks, Fragmentation | Ping of Death, IP source spoofing |
| **L4 Transport** | Port Scans, SYN Flood, TCP Anomalies, UDP Flood | Network reconnaissance, DDoS attacks |
| **L5 Session** | SSL Attacks, Session Hijacking, Auth Bypass, Brute Force | SSL stripping, credential stuffing |
| **L6 Presentation** | Encoding Attacks, Format Exploits, Crypto Attacks | XXE, weak cipher exploitation |
| **L7 Application** | Web Attacks (SQLi, XSS), DNS Threats, Malware C2, Protocol Abuse | SQL injection, DNS tunneling |

### Mobile Network Protection

Specialized protection for hotel WiFi, airports, and public networks:

- **Captive Portal Detection** — Safe handling of login portals
- **Evil Twin Detection** — Identifies rogue access points
- **SSL/TLS Interception Detection** — Alerts on HTTPS interception
- **DNS Security Verification** — Detects DNS hijacking
- **Network Trust Classification** — TRUSTED, VERIFIED, UNKNOWN, SUSPICIOUS, HOSTILE
- **VPN Recommendations** — Automatic VPN suggestions based on trust level

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

### OpenFlow SDN Integration

Guardian uses Open vSwitch (OVS) for software-defined networking:

```
┌─────────────────────────────────────────────────────────────────┐
│                     GUARDIAN SDN ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐ │
│   │                 GUARDIAN SDN CONTROLLER                   │ │
│   │            (OpenFlow 1.3 + REST API)                     │ │
│   └──────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                    OpenFlow Protocol                             │
│                              │                                   │
│   ┌──────────────────────────────────────────────────────────┐ │
│   │                  OPEN VSWITCH (OVS)                       │ │
│   │     ┌─────────────────────────────────────────────────┐  │ │
│   │     │                   br-guardian                    │  │ │
│   │     │  ┌────────┬────────┬────────┬────────┬───────┐  │  │ │
│   │     │  │ vlan10 │ vlan20 │ vlan30 │ vlan40 │  ...  │  │  │ │
│   │     │  │ lights │ thermo │ camera │ voice  │       │  │  │ │
│   │     │  └────────┴────────┴────────┴────────┴───────┘  │  │ │
│   │     └─────────────────────────────────────────────────┘  │ │
│   └──────────────────────────────────────────────────────────┘ │
│                              │                                   │
│              ┌───────────────┼───────────────┐                  │
│              │               │               │                  │
│           wlan0           eth0           wlan1                  │
│         (Hotspot)       (Bridge)       (Uplink)                 │
└─────────────────────────────────────────────────────────────────┘
```

**OpenFlow Features:**
- Dynamic flow rules based on MAC/IP/VLAN
- Automatic device classification
- QoS traffic shaping per VLAN
- Real-time flow statistics
- Threat-based flow blocking

### RADIUS Integration

MAC-based authentication with FreeRADIUS:

```
Client Device                Guardian                    FreeRADIUS
     │                          │                            │
     ├── Connect to WiFi ──────►│                            │
     │                          ├── Access-Request ─────────►│
     │                          │   (MAC: aa:bb:cc:dd:ee:ff) │
     │                          │                            │
     │                          │◄── Access-Accept ──────────┤
     │                          │   (VLAN: 30-Cameras)       │
     │◄── DHCP: 192.168.30.x ──┤                            │
     │                          │                            │
```

**RADIUS Features:**
- MAC-based VLAN assignment
- Device registration via web portal
- Guest network with captive portal
- Accounting for traffic tracking
- Integration with MSSP device registry

### HookProbe Transport Protocol (HTP)

Secure communication with MSSP cloud via UDP:

```
Guardian                                    mssp.hookprobe.com
    │                                              │
    ├──── HTP HELLO [node_id, W_fingerprint] ─────►│
    │                                              │
    │◄─── HTP CHALLENGE [nonce] ──────────────────┤
    │                                              │
    ├──── HTP ATTEST [PoSF signature] ────────────►│
    │                                              │
    │◄─── HTP ACCEPT [session_secret] ────────────┤
    │                                              │
    ├──── HTP DATA [encrypted telemetry] ─────────►│
    │                                              │
    ├──── HTP HEARTBEAT [every 30s] ──────────────►│
    │                                              │
```

**HTP Port**: UDP 4719

**HTP Features:**
- Keyless authentication (neural resonance)
- NAT/CGNAT traversal
- ChaCha20-Poly1305 encryption
- Anti-replay protection
- Automatic reconnection
- Bandwidth-adaptive streaming

### HTP File Transfer (File Access via MSSP)

Guardian provides secure remote file access through the MSSP using HTP (HookProbe Transport Protocol) with weight-bound encryption:

```
┌─────────────────────────────────────────────────────────────────┐
│                  HTP FILE TRANSFER ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│   [User Browser]                                                  │
│        │                                                          │
│        │ WSS/TLS (User ↔ MSSP)                                   │
│        ▼                                                          │
│   ┌─────────────┐                                                │
│   │    MSSP     │  (Relay only - cannot read content)            │
│   │    HTP      │                                                │
│   │    Relay    │                                                │
│   └──────┬──────┘                                                │
│          │                                                        │
│          │ WSS/HTP (MSSP ↔ Guardian)                             │
│          ▼                                                        │
│   ┌─────────────┐        ┌─────────────────────┐                 │
│   │  Guardian   │◄──────►│  Noise Protocol     │                 │
│   │   VPN       │        │  XX Pattern         │                 │
│   │  Service    │        │  X25519 + ChaCha20  │                 │
│   └──────┬──────┘        └─────────────────────┘                 │
│          │                                                        │
│          ▼                                                        │
│   ┌─────────────────────────────────────────┐                    │
│   │           Local File System              │                    │
│   │  /home  /opt/hookprobe  /var/log         │                    │
│   └─────────────────────────────────────────┘                    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**VPN Features:**
- **End-to-End Encryption** — MSSP cannot read file contents (Noise XX pattern)
- **X25519 Key Exchange** — Secure ephemeral key agreement
- **ChaCha20-Poly1305** — Authenticated encryption for all data
- **Path Restrictions** — Configurable allowed directories
- **File Operations** — List, read, write, stat files remotely
- **Chunked Transfer** — Large file support with 64KB chunks

**Supported Operations:**
- `FILE_LIST` — List directory contents
- `FILE_READ` — Read file contents
- `FILE_WRITE` — Write file contents
- `FILE_STAT` — Get file metadata (size, permissions, mtime)

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
| **nftables** | VLAN isolation firewall |
| **Open vSwitch** | OpenFlow SDN switching |
| **hostapd** | WiFi with dynamic VLAN |
| **FreeRADIUS** | MAC-based authentication |
| **dnsmasq** | Per-VLAN DHCP/DNS |
| **AdGuard DNS** | Ad blocking & DNS privacy |
| **HTP Client** | Secure MSSP communication |

---

## Installation

### Quick Install (Unified)

Guardian Liberty 5.0.0 uses a unified installation that includes all features:

```bash
# Clone HookProbe
git clone https://github.com/hookprobe/hookprobe
cd hookprobe

# Run unified Guardian setup
sudo ./install/guardian/scripts/setup.sh
```

**Included Features:**
- L1-L7 OSI Layer Threat Detection
- QSecBit AI-Powered Security Scoring
- Suricata IDS/IPS
- ModSecurity WAF
- XDP/eBPF High-Performance Packet Processing
- OpenFlow SDN Controller with OVS
- VLAN Segmentation (IoT Device Isolation)
- RADIUS MAC Authentication
- HTP File Transfer via MSSP (weight-bound encryption)
- HTP Secure Communication

### Configuration

After installation, customize Guardian via the configuration file:

```bash
# Edit configuration
sudo nano /etc/guardian/guardian.yaml
```

**Key Configuration Sections:**
- `radius:` — RADIUS server settings, MAC auth, secrets
- `vlans:` — VLAN definitions (10-80 for IoT, 999 for quarantine)
- `openflow:` — SDN controller settings
- `htp:` — MSSP connection settings
- `htp_file:` — HTP file transfer configuration
- `security:` — Threat detection thresholds
- `webui:` — Web interface settings

### Manual Installation

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y hostapd dnsmasq bridge-utils vlan \
    freeradius python3-flask nftables openvswitch-switch \
    python3-pyyaml python3-cryptography

# 2. Configure hostapd with dynamic VLAN
sudo cp install/guardian/config/hostapd.conf /etc/hostapd/
sudo cp install/guardian/config/hostapd.vlan /etc/hostapd/

# 3. Configure dnsmasq for per-VLAN DHCP
sudo cp install/guardian/config/dnsmasq.conf /etc/dnsmasq.d/guardian.conf

# 4. Configure Open vSwitch
sudo ovs-vsctl add-br br-guardian
sudo ovs-vsctl set-controller br-guardian tcp:127.0.0.1:6653

# 5. Install Guardian Python library
sudo cp -r install/guardian/lib /opt/hookprobe/guardian/

# 6. Create configuration
sudo mkdir -p /etc/guardian
sudo cp install/guardian/config/guardian.yaml /etc/guardian/

# 7. Enable services
sudo systemctl enable hostapd dnsmasq openvswitch-switch
sudo systemctl start hostapd dnsmasq openvswitch-switch
```

---

## Web Interface

Guardian includes a comprehensive web UI for monitoring and configuration:

**URL:** `http://192.168.4.1:8080`

### Features

#### Dashboard Tab
- **Security Overview** — RAG status for overall security, threats, IDS alerts
- **Threat Distribution Chart** — Visual bar chart of threat severity
- **Network Status** — WAN/LAN interface status, connected clients
- **Security Containers** — Status of all security services

#### Security Tab
- **Mobile Network Protection** — Trust level, VPN status, protection score
- **L2-L7 Layer Threats** — OSI layer breakdown visualization
- **Detection Coverage** — Threats by layer with severity counts
- **QSecBit Status** — AI threat detection status
- **Suricata Alerts** — Real-time IDS/IPS alerts with severity
- **Threat Log** — Historical threat data
- **IP Blocking (XDP)** — Block malicious IPs at kernel level
- **XDP Protection Stats** — Packets passed/dropped/rate-limited

#### SDN Tab
- **VLAN Segmentation** — Overview of IoT device isolation
- **VLAN Overview Table** — All VLANs with device counts, traffic stats
- **Connected Devices** — MAC addresses, IPs, hostnames, VLAN assignment
- **Device Actions** — Approve/quarantine devices
- **OVS Bridge Status** — Open vSwitch bridge and port information
- **OpenFlow Rules** — Active flow count

#### VPN Tab
- **HTP File Transfer Status** — Connection state to MSSP
- **Noise Protocol Handshake** — Encryption status
- **Traffic Statistics** — RX/TX bytes and packets
- **Active Sessions** — Current file access sessions
- **Allowed Paths** — Directories accessible via VPN
- **Recent File Transfers** — Log of file operations
- **VPN Actions** — Reconnect/disconnect controls

#### WiFi Tab
- **Hotspot Settings** — Configure SSID and password
- **Upstream WiFi** — Scan and connect to networks
- **Interface Status** — WAN/LAN interface details

#### System Tab
- **System Information** — Uptime, memory, disk, temperature
- **Container Management** — Start/stop security containers
- **System Actions** — Restart services, reboot

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/guardian/guardian.yaml` | **Main configuration file** |
| `/etc/hostapd/hostapd.conf` | WiFi AP configuration |
| `/etc/hostapd/hostapd.vlan` | VLAN-to-interface mapping |
| `/etc/dnsmasq.d/guardian.conf` | DHCP per VLAN |
| `/etc/freeradius/3.0/users` | MAC-to-VLAN mappings |
| `/etc/nftables.d/guardian-vlans.nft` | VLAN isolation rules |
| `/etc/openvswitch/conf.db` | OVS configuration |
| `/opt/hookprobe/guardian/lib/` | Python library modules |

### guardian.yaml Structure

```yaml
# /etc/guardian/guardian.yaml
radius:
  enabled: true
  secret: "your_radius_secret"
  mac_auth:
    enabled: true
    unknown_vlan: 999

vlans:
  smart_lights: { id: 10, subnet: "192.168.10.0/24" }
  thermostats: { id: 20, subnet: "192.168.20.0/24" }
  cameras: { id: 30, subnet: "192.168.30.0/24" }
  # ... etc

openflow:
  enabled: true
  controller_port: 6653
  ovs_bridge: "br-guardian"

htp:
  enabled: true
  mssp_host: "mssp.hookprobe.com"
  mssp_port: 8443

htp_file:
  enabled: true
  chunk_size: 8192
  verify_hash: true
  allowed_paths:
    - "/home"
    - "/srv/files"

security:
  threat_detection:
    enabled: true
    layers: ["L2", "L3", "L4", "L5", "L6", "L7"]
  qsecbit:
    amber_threshold: 0.45
    red_threshold: 0.70
```

---

## Network Architecture

### Component Communication

```
┌─────────────────────────────────────────────────────────────────┐
│                    HOOKPROBE NETWORK                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────┐     HTP (UDP 4719)     ┌──────────────────────┐  │
│   │ Guardian ├──────────────────────►│  mssp.hookprobe.com  │  │
│   │  (Edge)  │                        │       (MSSP)         │  │
│   └─────────┘                         └──────────┬───────────┘  │
│        │                                         │               │
│        │                                         │ HTP           │
│        │                                         │               │
│   ┌────┴────┐     HTP (UDP 4719)     ┌──────────┴───────────┐  │
│   │ Fortress ├──────────────────────►│       Nexus          │  │
│   │ (Local)  │                        │   (Aggregator)       │  │
│   └─────────┘                         └──────────────────────┘  │
│        │                                         │               │
│        │                                         │               │
│   ┌────┴────┐                        ┌──────────┴───────────┐  │
│   │Validator ├──────────────────────►│   DSM Validators     │  │
│   │ (Node)   │     HTP (UDP 4719)    │   (Consensus)        │  │
│   └─────────┘                         └──────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Local Network Topology

```
Internet ──► Router ──► Guardian wlan1 (client mode)
                            │
              ┌─────────────┼─────────────┐
              │             │             │
           wlan0          eth0         wlan2
         (2.4GHz AP)   (LAN bridge)   (5GHz AP)
              │             │             │
         ┌────┴────┐   ┌────┴────┐   ┌────┴────┐
         │  OVS    │   │  OVS    │   │  OVS    │
         │br-guard │   │br-guard │   │br-guard │
         └────┬────┘   └────┬────┘   └────┬────┘
              │             │             │
      ┌───────┼───────┬─────┼─────┬───────┼───────┐
      │       │       │     │     │       │       │
   VLAN10  VLAN20  VLAN30  ...  VLAN60  VLAN70  VLAN999
   Lights  Thermo  Camera      Phones  Robots  Quarantine
```

---

## Ports Used

| Port | Protocol | Service | Direction |
|------|----------|---------|-----------|
| 53 | UDP/TCP | DNS (dnsmasq) | Inbound |
| 67 | UDP | DHCP server | Inbound |
| 1812 | UDP | RADIUS authentication | Inbound |
| 1813 | UDP | RADIUS accounting | Inbound |
| 4719 | UDP | HTP (MSSP communication) | Outbound |
| 6653 | TCP | OpenFlow controller | Local |
| 8080 | TCP | Guardian web UI | Inbound |

---

## Service Management

```bash
# Core services
sudo systemctl status hostapd          # WiFi AP
sudo systemctl status dnsmasq          # DHCP/DNS
sudo systemctl status freeradius       # RADIUS
sudo systemctl status openvswitch-switch  # OVS
sudo systemctl status guardian-sdn     # SDN controller
sudo systemctl status guardian-webui   # Web interface
sudo systemctl status guardian-htp     # HTP client

# Security services
sudo systemctl status guardian-layer-detector  # L2-L7 threats
sudo systemctl status guardian-mobile-protection  # WiFi security
sudo systemctl status guardian-suricata     # IDS/IPS
sudo systemctl status guardian-zeek         # Network analysis
sudo systemctl status guardian-waf          # Web firewall
sudo systemctl status guardian-xdp          # DDoS protection
sudo systemctl status guardian-aggregator   # Threat correlation
sudo systemctl status guardian-adguard      # DNS filtering

# View connected clients
iw dev wlan0 station dump

# View DHCP leases
cat /var/lib/dnsmasq/dnsmasq.leases

# View OVS flows
sudo ovs-ofctl dump-flows br-guardian

# View firewall rules
sudo nft list ruleset

# View layer threats
cat /opt/hookprobe/guardian/data/layer_stats.json

# View HTP connection status
sudo journalctl -u guardian-htp -f
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

### Devices Not Getting VLAN

```bash
# Check RADIUS is running
sudo systemctl status freeradius

# Test RADIUS locally
radtest testing password 127.0.0.1 0 hookprobe_radius

# Check hostapd logs for VLAN assignment
sudo journalctl -u hostapd | grep -i vlan
```

### HTP Connection Failed

```bash
# Check HTP client status
sudo systemctl status guardian-htp

# Test UDP connectivity to MSSP
nc -u -v mssp.hookprobe.com 4719

# Check HTP logs
sudo journalctl -u guardian-htp -n 100

# Verify network allows UDP 4719 outbound
sudo nft list ruleset | grep 4719
```

### OVS Not Working

```bash
# Check OVS status
sudo systemctl status openvswitch-switch

# List bridges
sudo ovs-vsctl show

# Check controller connection
sudo ovs-vsctl get-controller br-guardian

# View flow table
sudo ovs-ofctl dump-flows br-guardian
```

---

## Related Documentation

- **[SDN Guide](../../docs/networking/SDN.md)** — Full SDN documentation
- **[HTP Protocol](../../docs/architecture/hookprobe-neuro-protocol.md)** — Transport protocol spec
- **[QSecBit](../../src/qsecbit/README.md)** — AI threat detection

### Python Library Modules (`lib/`)

| Module | Purpose |
|--------|---------|
| `layer_threat_detector.py` | L2-L7 OSI layer threat detection engine |
| `mobile_network_protection.py` | Hotel/public WiFi security |
| `guardian_agent.py` | QSecBit integration and unified reporting |
| `htp_client.py` | HookProbe Transport Protocol client |
| `openflow_controller.py` | OpenFlow 1.3 SDN controller |
| `radius_integration.py` | RADIUS/FreeRADIUS MAC authentication |
| `network_segmentation.py` | nftables-based VLAN isolation |
| `config.py` | Unified configuration management |
| `htp_file.py` | HTP file transfer with weight-bound encryption |

---

## Version History

| Version | Codename | Features |
|---------|----------|----------|
| 5.0.0 | **Liberty** | L2-L7 threat detection, mobile protection, OpenFlow SDN, HTP client |
| 4.0.0 | Sentinel | Basic VLAN segmentation, Suricata IDS |
| 3.0.0 | Pioneer | Multi-AP support, RADIUS |

---

**HookProbe Guardian** — *Liberty Cybersecurity for the Masses*

Version: 5.0.0 Liberty | MIT License
