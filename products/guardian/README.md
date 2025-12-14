# HookProbe Guardian

> **Take Control of Your Security, Anywhere You Go**

<p align="center">
  <strong>Enterprise Security for $75 · Full Visibility · Your Data, Your Control</strong>
</p>

---

## What Guardian Enables You to Achieve

Guardian transforms a Raspberry Pi into your personal security gateway. Connect to any network - hotel WiFi, coffee shops, airports - with complete visibility into what's being blocked and why.

**No black boxes. No hidden decisions. No data leaving your device.**

| What You Get | How It Empowers You |
|--------------|---------------------|
| **Transparent DNS blocking** | See exactly why each domain is blocked |
| **L2-L7 threat visibility** | Understand every security decision |
| **Portable protection** | Take enterprise security anywhere |
| **Data ownership** | Export everything - it's all yours |
| **Open source foundation** | Audit the code yourself |

**Version 5.0.0 Cortex** — See everything. Own your protection. Achieve more.

---

## The Guardian Promise

When you use Guardian, you're not trusting a black box - you're using transparent technology that shows you exactly what it's doing.

```
Traditional Security:              Guardian (Transparent):
"Something was blocked"      →     "ads.tracker.com blocked:
                                    ML confidence 94%,
                                    Category: ADVERTISING,
                                    Reason: High entropy (4.2),
                                    CNAME resolves to demdex.net"
```

Every decision is explainable. Every action is auditable. Your data never leaves your device.

---

## What You Achieve with Guardian

### 1. Connect Anywhere with Confidence

Hotel WiFi, airport networks, coffee shop hotspots - they're all risky. Guardian creates a secure bubble around your devices.

```
┌─────────────────────────────────────────────────────────────────┐
│                    YOUR SECURE BUBBLE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Untrusted WiFi ──► Guardian ──► Your Devices                  │
│   (Hotel/Airport)      │          (Laptop, Phone, Tablet)       │
│                        │                                        │
│                   ┌────┴────┐                                   │
│                   │ You see │                                   │
│                   │ everything │                                │
│                   │ happening │                                 │
│                   └─────────┘                                   │
│                                                                  │
│   What Guardian shows you:                                       │
│   - Every blocked threat and why                                │
│   - Every DNS query and its classification                      │
│   - Every suspicious activity at every network layer            │
│   - Real-time security score with full explanation              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2. Block Ads and Trackers - Know Why

Guardian doesn't just block - it explains:

```
Domain: doubleclick.net
Decision: BLOCKED
Method: ML Classification + Blocklist
Confidence: 98%
Category: ADVERTISING
Why:
  - Known advertising network (blocklist)
  - High ad-pattern score (0.89)
  - CNAME chain contains: ad.doubleclick.net → pagead2.googlesyndication.com

Your choice: [Whitelist] [Keep Blocked] [View Details]
```

### 3. Detect Threats Across All Network Layers

See what's happening at every level:

| Layer | What Guardian Detects | What You See |
|-------|----------------------|--------------|
| **L2** | ARP Spoofing, Evil Twin, Rogue DHCP | "MAC address changed for gateway - possible attack" |
| **L3** | IP Spoofing, ICMP Flood | "Unusual ICMP traffic from 192.168.1.50" |
| **L4** | Port Scans, SYN Flood | "50 connection attempts to different ports" |
| **L5** | SSL Stripping, TLS Downgrade | "Someone tried to downgrade your connection" |
| **L7** | SQL Injection, XSS, DNS Tunneling | "Suspicious query pattern blocked" |

**Every detection includes:** What happened, why it's suspicious, what Guardian did, and what you can do.

### 4. Join the Collective Without Losing Privacy

Guardian connects to the global HookProbe mesh - but your data stays yours.

**What Guardian shares:**
- Anonymized threat signatures (no source info)
- ML model weight updates (not your queries)
- Attack patterns (source removed)

**What Guardian NEVER shares:**
- Your IP address
- Your DNS queries
- Your browsing history
- Any identifiable information

You benefit from global threat intelligence while keeping everything private.

---

## Quick Start

```bash
# First-time setup (fresh Raspberry Pi)
sudo apt update && sudo apt install -y git

# Clone and install
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
sudo ./install.sh --tier guardian
```

**That's it!** The install script handles everything automatically:
- All system packages (hostapd, dnsmasq, suricata, python3, etc.)
- Python dependencies
- Locale configuration (en_US.UTF-8)
- WiFi country auto-detection from your location
- Network interface setup (wlan0 for WAN, wlan1 for AP)
- Service configuration and startup

**After installation:**
1. Connect to **HookProbe-Guardian** WiFi
2. Open **http://192.168.4.1:8080**

**Time to protection:** ~5 minutes
**Ongoing effort:** Zero - it learns and adapts automatically

---

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Platform | Raspberry Pi 4 (2GB) | Raspberry Pi 5 (4GB) |
| RAM | 1.5GB | 2-4GB |
| Storage | 16GB microSD | 32GB+ microSD (A2 rated) |
| Network | 1x WiFi (built-in) + 1x USB WiFi | 2x WiFi interfaces |
| Cost | ~$75 total | ~$100 total |

**That's enterprise security for the cost of a nice dinner.**

---

## The Dashboard - Full Visibility

Access at `http://192.168.4.1:8080`

### Dashboard Tab - Your Security at a Glance
- **Qsecbit Score** with full breakdown of why
- **Network status** - what's connected, what's happening
- **Threat summary** - recent detections with explanations

### Security Tab - Deep Dive
- **L2-L7 threat breakdown** - see every layer
- **Mobile network trust level** - understand your risk
- **Real-time IDS alerts** - Suricata explanations
- **XDP statistics** - kernel-level protection details

### DNS Protection Tab - Explainable Blocking
- **Every blocked domain with reason**
- **ML classification confidence scores**
- **CNAME chain visibility** - see the hidden trackers
- **Whitelist controls** - your choice, always

### Devices Tab - Know What's Connected
- **Every device on your network**
- **MAC addresses and hostnames**
- **Connection history**
- **Export capability** - your data is yours

### System Tab - Full Transparency
- **Service status and logs**
- **Resource usage**
- **Update controls**
- **Debug CLI** - full diagnostic access

### Cortex Tab - See Your Mesh
- **3D visualization** of your security posture
- **Real-time attack visualization**
- **Mesh connectivity status**
- **Your contribution to collective defense**

---

## Technical Transparency

### dnsXai - Explainable DNS Protection

Guardian uses dnsXai for AI-powered DNS filtering. Every decision is transparent:

```python
# This is the actual classification output you see:
{
    "domain": "suspicious-tracker.com",
    "decision": "BLOCKED",
    "confidence": 0.92,
    "category": "TRACKING",
    "features": {
        "shannon_entropy": 4.2,
        "ad_pattern_score": 0.15,
        "cname_uncloaked": "adobe.demdex.net",
        "blocklist_match": false,
        "ml_classification": "TRACKING"
    },
    "explanation": "High entropy domain resolving to known tracker"
}
```

### Qsecbit - Transparent Threat Scoring

The security score isn't magic - it's math you can verify:

```
Qsecbit = 0.30×threats + 0.20×mobile + 0.25×ids + 0.15×xdp + 0.02×network + 0.08×dnsxai

Current Score: 0.32 (GREEN)
├── Threats component: 0.10 (low threat activity)
├── Mobile component: 0.15 (trusted network)
├── IDS component: 0.08 (no alerts)
├── XDP component: 0.12 (normal traffic)
├── Network component: 0.05 (stable)
└── dnsXai component: 0.18 (some ads blocked)
```

### Security Stack - All Auditable

| Component | Purpose | Transparency |
|-----------|---------|--------------|
| **dnsXai** | DNS protection | Every block explained |
| **Suricata** | IDS/IPS | Alert details visible |
| **XDP/eBPF** | DDoS protection | Stats and rules shown |
| **Layer Detector** | L2-L7 analysis | Detection reasoning exposed |
| **Mesh Agent** | Collective intelligence | Contribution visible |

---

## Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GUARDIAN ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Untrusted Network (Hotel WiFi, Airport, etc.)                 │
│                              │                                   │
│                              ▼                                   │
│                   ┌──────────────────┐                          │
│                   │   Guardian (RPi)  │                          │
│                   │   192.168.4.1     │                          │
│                   │                   │                          │
│                   │  ┌─────────────┐ │                          │
│                   │  │ You can see │ │                          │
│                   │  │ everything  │ │                          │
│                   │  │ happening   │ │                          │
│                   │  └─────────────┘ │                          │
│                   └────────┬─────────┘                          │
│                            │                                     │
│                  Your Secure Hotspot                             │
│                  "HookProbe-Guardian"                            │
│                            │                                     │
│              ┌─────────────┼─────────────┐                      │
│              │             │             │                      │
│           Laptop        Phone        Tablet                     │
│         192.168.4.2   192.168.4.3   192.168.4.4                │
│                                                                  │
│   All traffic inspected · All decisions visible · All data yours│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Feature Summary

| Feature | What It Does | What You See |
|---------|--------------|--------------|
| **Secure WiFi Hotspot** | Creates protected network | Connection stats, signal strength |
| **L2-L7 Detection** | Monitors all layers | Every threat with explanation |
| **dnsXai** | Blocks ads/trackers | Every block with reasoning |
| **Mobile Protection** | Detects hostile networks | Trust level and why |
| **IDS/IPS** | Intrusion detection | Alert details and context |
| **XDP DDoS** | Kernel-level protection | Packet stats and rules |
| **Mesh Networking** | Collective defense | Your contribution visible |
| **Web Dashboard** | Full visibility | Everything at a glance |
| **Data Export** | Your data, your choice | Export all logs anytime |

---

## Guardian vs Fortress

Guardian is designed for simplicity and portability. For advanced features, consider Fortress.

| Feature | Guardian | Fortress |
|---------|----------|----------|
| **Use Case** | Travel, personal | Business, permanent |
| **Network** | Single network | Multi-VLAN |
| **Complexity** | Simple | Advanced |
| **Setup Time** | 5 minutes | 30+ minutes |
| **Transparency** | Full | Full |
| **Data Ownership** | Complete | Complete |

**Both tiers:** Same transparency, same data ownership, same empowerment.

---

## Troubleshooting

### Can't connect to hotspot?
```bash
# Check if hostapd is running
systemctl status hostapd

# View the logs
journalctl -u hostapd -n 50

# Guardian shows you exactly what's happening
```

### Want to understand a block?
- Open Dashboard → DNS Protection
- Find the domain
- Click for full explanation including ML features, CNAME chain, and blocklist sources

### Need to whitelist something?
- Dashboard → DNS Protection → Whitelist
- Add domain with one click
- See the effect immediately

---

## The Guardian Difference

**Other security tools:** "Trust us, we're protecting you"
**Guardian:** "Here's exactly what we're doing and why"

1. **Full visibility** into every security decision
2. **Complete data ownership** - export everything, anytime
3. **Open source foundation** - audit the code yourself
4. **Collective defense** - benefit from the mesh while keeping privacy
5. **Enterprise capability** for $75

**This is what security looks like when you're in control.**

---

**HookProbe Guardian v5.0** — *See everything. Own your protection. Achieve more.*

AGPL v3.0 License (Open Source)
