# HookProbe SDN - Portable Software-Defined Networking

<p align="center">
  <strong>Plug-and-Play IoT Network Segmentation</strong><br>
  <em>MAC-Based VLAN · Zero-Config Setup · Enterprise Security in Minutes</em>
</p>

---

## Why You Need SDN for IoT

### The Problem: IoT Devices Are a Security Nightmare

Your smart home or business has dozens of IoT devices:

- 💡 Smart lights (Philips Hue, LIFX)
- 🌡️ Thermostats (Nest, Ecobee)
- 📷 Security cameras (Ring, Wyze, Hikvision)
- 🔊 Voice assistants (Alexa, Google Home)
- 🤖 Robot vacuums (Roomba, Roborock)
- 📺 Smart TVs and streaming devices
- 🚪 Smart locks and doorbells

**The danger**: These devices often:
- Run outdated firmware with known vulnerabilities
- Phone home to servers in foreign countries
- Can be hijacked to attack other devices on your network
- Have weak or no authentication

**Real attacks that happened:**
- **2016 Mirai botnet**: Compromised 600,000 IoT devices for massive DDoS
- **2019 Ring camera hacks**: Attackers talked to children through cameras
- **2020 Philips Hue vulnerability**: Light bulbs used to attack home networks
- **2023 Robot vacuum espionage**: Vacuums caught sending photos to cloud

### Traditional Solutions Don't Work

| Approach | Why It Fails |
|----------|--------------|
| **Trust your router** | Consumer routers lack VLAN support |
| **Separate WiFi networks** | Need multiple APs, complex setup |
| **IoT-specific routers** | $300-500, vendor lock-in |
| **Enterprise switches** | Requires networking expertise |
| **Just hope for the best** | One compromised device owns everything |

### The HookProbe Solution: Portable Plug-and-Play SDN

**Guardian transforms a $75 Raspberry Pi into an enterprise-grade SDN controller.**

```
┌────────────────────────────────────────────────────────────────────┐
│                     YOUR HOME/BUSINESS                              │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                    GUARDIAN (RPi 4/5)                        │ │
│  │                                                              │ │
│  │  ┌─────────────┐   Single SSID: "MyHome"                    │ │
│  │  │   WiFi AP   │   All devices connect to same network      │ │
│  │  │  (hostapd)  │   Guardian auto-assigns to VLANs           │ │
│  │  └──────┬──────┘                                            │ │
│  │         │                                                    │ │
│  │  ┌──────▼──────┐                                            │ │
│  │  │   RADIUS    │   MAC → VLAN mapping                       │ │
│  │  │  (local)    │   Unknown → Quarantine                     │ │
│  │  └──────┬──────┘                                            │ │
│  │         │                                                    │ │
│  │  ┌──────▼──────────────────────────────────────────────┐    │ │
│  │  │              VLAN Bridge (nftables)                  │    │ │
│  │  │                                                      │    │ │
│  │  │  VLAN 10    VLAN 20    VLAN 30    VLAN 40   VLAN 999│    │ │
│  │  │  Lights    Thermo     Cameras    Voice    Quarantine│    │ │
│  │  │    │          │          │         │          │     │    │ │
│  │  │    │    ╳     │    ╳     │   ╳     │    ╳     │     │    │ │
│  │  │    │  BLOCKED │  BLOCKED │ BLOCKED │  BLOCKED │     │    │ │
│  │  │    ▼          ▼          ▼         ▼          ▼     │    │ │
│  │  └─────────────────────────────────────────────────────┘    │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                    │
│     💡 💡 💡      🌡️        📷 📷       🔊 🔊      ❓ ❓          │
│     Lights      Thermo     Cameras     Voice     Unknown          │
│   192.168.10.x  .20.x      .30.x       .40.x     .99.x            │
│                                                                    │
│   ✓ Each category isolated - cameras can't see lights            │
│   ✓ Compromised device can't spread to others                    │
│   ✓ Internet access per-category (cameras: cloud only)           │
│   ✓ Unknown devices quarantined until registered                 │
└────────────────────────────────────────────────────────────────────┘
```

---

## Key Benefits

### 1. True Plug-and-Play

- **5-minute setup** — Plug in Guardian, connect to web UI, done
- **No networking expertise** — Web interface guides you through everything
- **Works with existing router** — Guardian bridges to your upstream WiFi
- **No infrastructure changes** — No new switches, cables, or router configuration

### 2. Single SSID, Multiple VLANs

- **One network name** — All devices connect to "MyHome"
- **Automatic segmentation** — Guardian assigns VLANs based on MAC address
- **Seamless roaming** — Devices don't know they're segmented
- **Easy onboarding** — Register device once, forget about it

### 3. Enterprise Security for $75

| Feature | Enterprise Cost | HookProbe Guardian |
|---------|-----------------|-------------------|
| VLAN-capable switch | $200-500 | Built-in |
| RADIUS server | $5,000+/year | Built-in |
| Network management | $10,000+/year | Free web UI |
| Professional setup | $2,000+ | DIY in 5 minutes |
| **Total** | **$17,000+** | **$75** |

### 4. Portable Security

**Take your network security with you:**

- **Moving house?** Unplug Guardian, plug in at new location
- **Traveling?** Guardian secures hotel/Airbnb WiFi
- **Remote office?** Instant secure network anywhere
- **Events/Pop-ups?** Temporary secure network in minutes

### 5. Defense in Depth

```
Layer 1: MAC-based VLAN assignment (prevent lateral movement)
Layer 2: Inter-VLAN firewall (nftables/iptables)
Layer 3: Per-VLAN internet policy (allow/deny/restrict)
Layer 4: Qsecbit anomaly detection (AI-powered threat detection)
Layer 5: HTP tunnel to MSSP (professional monitoring)
```

---

## How It Works

### MAC-Based VLAN Assignment

When a device connects to Guardian's WiFi:

```
1. Device sends association request with MAC address
2. hostapd queries FreeRADIUS with MAC
3. RADIUS returns VLAN assignment (or quarantine)
4. hostapd places device in assigned VLAN
5. Device gets IP from VLAN-specific DHCP pool
6. nftables enforces inter-VLAN isolation
```

### Device Registration Flow

```
┌─────────────────────────────────────────────────────────────┐
│  NEW DEVICE CONNECTS                                        │
│                                                             │
│  1. Device: "I want to join MyHome WiFi"                   │
│                    ↓                                        │
│  2. Guardian: "What's your MAC? AA:BB:CC:DD:EE:FF"         │
│                    ↓                                        │
│  3. RADIUS lookup: "Unknown MAC → Quarantine VLAN 999"     │
│                    ↓                                        │
│  4. Device gets IP: 192.168.99.x (isolated, no internet)   │
│                    ↓                                        │
│  5. User sees device in Guardian web UI                     │
│                    ↓                                        │
│  6. User assigns category: "This is a smart light"         │
│                    ↓                                        │
│  7. RADIUS updated: AA:BB:CC:DD:EE:FF → VLAN 10            │
│                    ↓                                        │
│  8. Device reconnects, now on VLAN 10 (192.168.10.x)       │
│                    ↓                                        │
│  9. Light works normally, isolated from cameras/thermostats │
└─────────────────────────────────────────────────────────────┘
```

---

## Pre-Configured VLAN Structure

Guardian comes with sensible defaults:

| VLAN ID | Name | Subnet | Internet | Use Case |
|---------|------|--------|----------|----------|
| 1 | Management | 192.168.1.0/24 | Full | Guardian admin, trusted devices |
| 10 | Lights | 192.168.10.0/24 | Cloud only | Smart bulbs, LED strips |
| 20 | Climate | 192.168.20.0/24 | Cloud only | Thermostats, sensors |
| 30 | Cameras | 192.168.30.0/24 | Cloud only | Security cameras, doorbells |
| 40 | Voice | 192.168.40.0/24 | Cloud only | Alexa, Google Home |
| 50 | Appliances | 192.168.50.0/24 | Cloud only | Smart fridges, washers |
| 60 | Entertainment | 192.168.60.0/24 | Full | Smart TVs, streaming |
| 70 | Robots | 192.168.70.0/24 | Cloud only | Vacuums, lawn mowers |
| 80 | Sensors | 192.168.80.0/24 | Denied | Motion, door/window sensors |
| 999 | Quarantine | 192.168.99.0/24 | Denied | Unregistered devices |

**"Cloud only"** = Can reach cloud services but not local network or arbitrary internet

---

## Hardware Setup

### Basic Setup (Single AP)

```
┌─────────────────────────────────────────┐
│  Raspberry Pi 4/5 with built-in WiFi    │
│                                         │
│  ┌─────────┐    ┌─────────┐            │
│  │ wlan0   │    │  eth0   │            │
│  │ Hotspot │    │   LAN   │            │
│  │  (AP)   │    │ Bridge  │            │
│  └────┬────┘    └────┬────┘            │
│       │              │                  │
│       ▼              ▼                  │
│   IoT Devices    Wired Devices          │
└─────────────────────────────────────────┘
```

**Covers**: ~30m radius, ~20-30 simultaneous devices

### Extended Setup (Multi-AP with USB)

For larger homes, businesses, or better coverage, add USB WiFi adapters:

```
┌──────────────────────────────────────────────────────────────────┐
│  Raspberry Pi 5 with USB WiFi Adapters                           │
│                                                                  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────┐ │
│  │ wlan0   │  │ wlan1   │  │ wlan2   │  │ wlan3   │  │  eth0  │ │
│  │ 2.4GHz  │  │  5GHz   │  │ 2.4GHz  │  │  5GHz   │  │  LAN   │ │
│  │ Hotspot │  │ Uplink  │  │   AP    │  │   AP    │  │ Bridge │ │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └───┬────┘ │
│       │            │            │            │            │      │
│       ▼            ▼            ▼            ▼            ▼      │
│   Ground       Internet      1st         2nd          Wired     │
│   Floor        Uplink       Floor       Floor        Devices    │
└──────────────────────────────────────────────────────────────────┘
```

**Recommended USB WiFi Adapters:**

| Adapter | Chipset | Band | Driver | Price |
|---------|---------|------|--------|-------|
| **Alfa AWUS036ACM** ⭐ | MT7612U | Dual | Native | $35 |
| **TP-Link Archer T3U Plus** | RTL8812BU | Dual | DKMS | $25 |
| **Panda PAU09** | RT5572 | Dual | Native | $30 |
| **Alfa AWUS036ACS** | RTL8811AU | Dual | DKMS | $28 |

**Requirements for USB adapters:**
- AP mode support (not all adapters support this!)
- Linux driver availability
- 5GHz support recommended for less interference

### Maximum Configuration (4 APs)

Raspberry Pi 5 has 2x USB 3.0 + 2x USB 2.0 ports. With a powered USB hub:

```
                    Raspberry Pi 5
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   USB 3.0 Hub      USB 3.0 Port      Built-in
        │                │              wlan0
   ┌────┴────┐           │           (2.4GHz AP)
   │         │           │
 wlan2     wlan3       wlan1
(5GHz AP) (5GHz AP)  (Uplink to
                      Internet)
```

**This gives you:**
- **4 access points** (1 built-in + 3 USB)
- **Whole-building coverage** for homes up to 5,000 sq ft
- **Band steering** (2.4GHz for IoT, 5GHz for phones/laptops)
- **Redundancy** if one AP fails

---

## Web Interface

Guardian's web UI runs at `http://192.168.1.1:8080`

### Dashboard
- Overview of connected devices
- VLAN statistics
- Recent activity

### Device Management
- Register new devices
- Assign categories
- Block/unblock devices
- View device history

### Network Setup
- Scan for upstream WiFi
- Connect to internet
- Configure hotspot SSID/password
- Bridge LAN port

### VLAN Configuration
- Create custom VLANs
- Set internet policies
- Configure DHCP ranges
- Define firewall rules

---

## Security Policies

### Per-Category Internet Access

| Policy | Description | Example |
|--------|-------------|---------|
| **Full** | Unrestricted internet | Phones, laptops |
| **Cloud Only** | Only manufacturer servers | Smart lights, thermostats |
| **Restricted** | Whitelist only | Security cameras |
| **Denied** | No internet access | Local sensors |

### Cloud-Only Implementation

"Cloud Only" policy allows devices to reach their cloud services while blocking everything else:

```
# Example: Allow Philips Hue cloud only
iptables -A FORWARD -s 192.168.10.0/24 -d 18.194.126.27 -j ACCEPT  # Hue cloud
iptables -A FORWARD -s 192.168.10.0/24 -d 54.93.162.185 -j ACCEPT  # Hue cloud
iptables -A FORWARD -s 192.168.10.0/24 -j DROP                      # Block all else
```

Guardian auto-detects many IoT devices and applies appropriate policies.

---

## Integration with HookProbe Ecosystem

### MSSP Monitoring

Guardian connects to Fortress/Nexus via HTP tunnel:

```
Guardian (Edge) ──HTP──→ Fortress/Nexus (MSSP)
                              │
                    ┌─────────┴─────────┐
                    │                   │
              Central RADIUS      Threat Intelligence
              (MAC→VLAN sync)     (Anomaly detection)
```

**Benefits:**
- Centralized device management across multiple sites
- Cross-network threat intelligence
- Professional security monitoring
- Automatic policy updates

### Qsecbit Integration

Guardian runs Qsecbit for local threat detection:

```
Device behavior anomaly detected:
  Device: Smart Light (192.168.10.45)
  Anomaly: Unusual outbound traffic to 91.134.x.x (Russia)
  Qsecbit Score: 0.82 (RED)
  Action: Device moved to Quarantine VLAN
  Alert: Sent to MSSP dashboard
```

---

## Comparison with Alternatives

| Feature | Consumer Router | UniFi | Cisco Meraki | **HookProbe Guardian** |
|---------|----------------|-------|--------------|----------------------|
| VLAN support | ❌ | ✅ | ✅ | ✅ |
| MAC-based assignment | ❌ | ✅ | ✅ | ✅ |
| Price | $50-200 | $200-500 | $500-1000 | **$75** |
| Setup time | N/A | Hours | Hours | **5 minutes** |
| Cloud required | No | Optional | **Required** | No |
| Subscription | No | No | **$150/year** | No |
| Portable | No | No | No | **Yes** |
| AI threat detection | No | No | Basic | **Qsecbit** |
| Open source | No | No | No | **MIT License** |

---

## Quick Start

### 1. Flash Guardian Image

```bash
# Download Guardian image
wget https://hookprobe.com/releases/guardian-5.0.0.img.xz

# Flash to SD card (replace /dev/sdX with your SD card)
xzcat guardian-5.0.0.img.xz | sudo dd of=/dev/sdX bs=4M status=progress
```

### 2. Boot and Connect

1. Insert SD card into Raspberry Pi 4/5
2. Connect Ethernet (optional) or power only
3. Pi boots and creates WiFi network: `HookProbe-Guardian-Setup`
4. Connect to this network with your phone/laptop

### 3. Configure via Web UI

1. Open browser to `http://192.168.1.1:8080`
2. Select your home WiFi network
3. Enter WiFi password
4. Set Guardian hotspot name and password
5. Done! Connect your IoT devices to new hotspot

### 4. Register Devices

1. Connect each IoT device to Guardian WiFi
2. Open Guardian web UI → Devices
3. New devices appear in "Quarantine"
4. Click device → Assign category → Save
5. Device automatically moves to correct VLAN

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Can't connect to Guardian WiFi | Check power, wait 2 min for boot |
| Web UI not loading | Try `http://192.168.1.1:8080` |
| No internet on devices | Check upstream WiFi connection |
| Device not getting IP | Check DHCP server, restart dnsmasq |
| Device in wrong VLAN | Re-register device, restart hostapd |

---

## Related Documentation

- **[VPN Remote Access](VPN.md)** — Access your SDN-protected network remotely
- **[Guardian Installation](../../install/guardian/README.md)** — Detailed setup guide
- **[USB AP Configuration](../../install/guardian/README.md#multi-ap)** — Extending with USB adapters
- **[Qsecbit AI Detection](../../src/qsecbit/README.md)** — Threat detection algorithms

---

**HookProbe SDN** — *Enterprise Network Segmentation for Everyone*

Version: 5.0.0 | MIT License
