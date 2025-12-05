# HookProbe VPN - Secure Remote Access

<p align="center">
  <strong>Access Your Protected Network from Anywhere</strong><br>
  <em>IKEv2 Native VPN · HTP Tunnel · Zero-Config Mobile Access</em>
</p>

---

## Why You Need VPN with HookProbe

### The Problem

Your Guardian or Fortress device protects your home or business network, but:

- **You're not always home** — Traveling, at work, or on mobile
- **Your devices are behind NAT/CGNAT** — No public IP address
- **Public WiFi is dangerous** — Coffee shops, hotels, airports are attack vectors
- **You need access to local resources** — Cameras, NAS, smart home, internal apps

### Traditional Solutions Fall Short

| Approach | Problem |
|----------|---------|
| Port forwarding | Exposes your network to the internet |
| Dynamic DNS | Still requires open ports, complex setup |
| Cloud relay services | Third-party sees your traffic, subscription fees |
| Consumer VPNs | Protects you FROM the internet, not TO your network |

### The HookProbe Solution

**HookProbe VPN creates a secure tunnel from your phone/laptop directly to your protected network.**

```
┌─────────────────────────────────────────────────────────────────┐
│  YOU (Anywhere in the World)                                    │
│                                                                 │
│   📱 iPhone/Android          💻 Laptop                         │
│   Native IKEv2 VPN           Native IKEv2 VPN                  │
│         │                           │                          │
│         └───────────┬───────────────┘                          │
│                     │ Encrypted Tunnel                         │
│                     ▼                                          │
│         ┌───────────────────┐                                  │
│         │      Nexus        │  ← MSSP Cloud (Public IP)        │
│         │   VPN Gateway     │                                  │
│         └─────────┬─────────┘                                  │
│                   │ HTP Tunnel                                 │
│                   ▼                                            │
│  ┌────────────────────────────────────────┐                    │
│  │  Your Home/Business (No Public IP)     │                    │
│  │                                         │                   │
│  │   Guardian/Fortress ← Protected        │                   │
│  │        │                                │                   │
│  │   ┌────┴────┬────────┬────────┐        │                   │
│  │   📷       💡       🌡️        📁       │                   │
│  │ Cameras  Lights  Thermostat   NAS      │                   │
│  └────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Benefits

### 1. Zero-Config Mobile Access

- **Native VPN protocols** — Works with built-in iOS/Android VPN clients
- **One-click profile import** — Download .mobileconfig or JSON profile
- **No app required** — Uses standard IKEv2/IPsec
- **Automatic reconnection** — Seamlessly switches between WiFi and cellular

### 2. Works Behind Any NAT

- **No port forwarding needed** — Guardian initiates outbound HTP connection
- **CGNAT compatible** — Works with any ISP, even mobile carriers
- **No public IP required** — Your network stays invisible to the internet

### 3. Enterprise-Grade Security

- **IKEv2 with EAP-TLS** — Certificate-based authentication
- **Perfect Forward Secrecy** — New keys for every session
- **256-bit encryption** — AES-256-GCM or ChaCha20-Poly1305
- **Integration with LogMe2** — SSO with your existing identity provider

### 4. Bandwidth Allocation & QoS

- **Per-user bandwidth limits** — Prevent single user from hogging connection
- **Traffic prioritization** — Real-time video > bulk downloads
- **Dormant mode** — Minimal resource usage when idle

---

## Architecture

### Two-Segment Tunnel Design

HookProbe VPN uses a **two-segment architecture** for maximum compatibility:

```
Segment 1: Phone ←──IKEv2──→ Nexus (Standard VPN Protocol)
Segment 2: Nexus ←──HTP────→ Guardian (HookProbe Transport Protocol)
```

**Why this design?**

1. **Mobile compatibility** — iOS/Android natively support IKEv2
2. **NAT traversal** — HTP handles the complex NAT/CGNAT traversal
3. **Security** — Each segment is independently encrypted
4. **Flexibility** — Add new edge devices without mobile reconfiguration

### Protocol Stack

| Layer | Segment 1 (Phone→Nexus) | Segment 2 (Nexus→Guardian) |
|-------|-------------------------|----------------------------|
| Encryption | AES-256-GCM | ChaCha20-Poly1305 |
| Auth | EAP-TLS (X.509 certs) | Neural Resonance |
| Transport | IKEv2/IPsec | HTP over UDP |
| NAT Traversal | IKE NAT-T (UDP 4500) | HTP built-in |

---

## Setup Guide

### For Users (Mobile App)

1. **Log into MSSP Dashboard** at `https://dashboard.hookprobe.com`
2. **Navigate to VPN** → **Generate Profile**
3. **Select your device** (iPhone, Android, Windows, macOS)
4. **Download profile** and import:
   - **iOS**: Open .mobileconfig → Settings → VPN
   - **Android**: Open strongSwan app → Import profile
   - **Windows**: Run PowerShell script as Administrator
   - **macOS**: Open .mobileconfig → System Preferences → VPN

### For Administrators (MSSP)

1. **Deploy VPN Gateway** on Nexus:
   ```bash
   cd /opt/hookprobe/install/nexus/vpn
   sudo ./setup-vpn-gateway.sh
   ```

2. **Configure FreeRADIUS** for user authentication:
   ```bash
   sudo systemctl enable freeradius
   sudo systemctl start freeradius
   ```

3. **Generate CA and server certificates**:
   ```bash
   python3 -m apps.vpn.management.commands.init_ca
   ```

4. **Enable VPN in Django settings**:
   ```python
   INSTALLED_APPS += ['apps.vpn']
   ```

---

## Use Cases

### Home Users

| Scenario | How VPN Helps |
|----------|---------------|
| **Travel security** | Route all traffic through your home network |
| **Check cameras** | View security cameras from anywhere |
| **Access NAS** | Stream media, access files remotely |
| **Smart home** | Control devices without cloud exposure |

### Business Users

| Scenario | How VPN Helps |
|----------|---------------|
| **Remote work** | Secure access to internal applications |
| **Branch offices** | Connect satellite offices to HQ |
| **Field technicians** | Access customer systems securely |
| **Compliance** | Audit trail of all remote access |

### MSSP Providers

| Scenario | How VPN Helps |
|----------|---------------|
| **Customer access** | Technicians connect to customer networks |
| **Multi-tenant** | One VPN gateway serves all customers |
| **Billing** | Track bandwidth usage per customer |
| **Support** | Remote troubleshooting without site visits |

---

## Security Considerations

### What's Protected

- **Authentication**: X.509 certificates with 2048-bit RSA or P-256 ECDSA
- **Key Exchange**: IKEv2 with Diffie-Hellman Group 14/19/20
- **Encryption**: AES-256-GCM (hardware accelerated on modern CPUs)
- **Integrity**: HMAC-SHA256 or Poly1305

### What's NOT Protected

- **Endpoint security** — VPN doesn't protect against malware on your device
- **Credential theft** — Protect your certificate with a strong password
- **Physical access** — Stolen devices with saved credentials are a risk

### Best Practices

1. **Use certificate authentication** — Never use pre-shared keys
2. **Set certificate expiry** — Rotate certificates annually
3. **Enable MFA** — Require second factor for VPN access
4. **Monitor connections** — Review VPN logs regularly
5. **Revoke on termination** — Immediately revoke access when employees leave

---

## Bandwidth & Performance

### Expected Performance

| Connection Type | Typical Throughput | Latency Overhead |
|-----------------|-------------------|------------------|
| Home broadband (100 Mbps) | 80-90 Mbps | +5-15 ms |
| Mobile 4G LTE | 20-40 Mbps | +20-50 ms |
| Mobile 5G | 100-300 Mbps | +10-30 ms |
| Hotel WiFi | 5-20 Mbps | +30-100 ms |

### Bandwidth Allocation

Administrators can set per-user bandwidth limits:

```python
# In Django admin or API
VPNProfile.objects.create(
    user=user,
    bandwidth_limit_mbps=50,  # Max 50 Mbps
    priority='interactive',   # Higher QoS priority
)
```

### QoS Traffic Classes

| Class | Priority | Use Case |
|-------|----------|----------|
| `realtime` | Highest | VoIP, video calls |
| `interactive` | High | SSH, remote desktop |
| `bulk` | Normal | File transfers, browsing |
| `background` | Low | Backups, updates |

---

## Troubleshooting

### Connection Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| "Authentication failed" | Certificate expired | Regenerate VPN profile |
| "Server unreachable" | Nexus firewall | Open UDP 500, 4500 |
| "Connection timeout" | NAT issues | Check HTP tunnel status |
| Slow speeds | Bandwidth limit | Check user quota |

### Checking VPN Status

```bash
# On Nexus (VPN Gateway)
sudo swanctl --list-sas      # Active VPN sessions
sudo swanctl --list-conns    # Configured connections

# On Guardian (Edge Device)
systemctl status hookprobe-htp  # HTP tunnel status
```

### Logs

```bash
# VPN gateway logs
journalctl -u strongswan -f

# Django VPN app logs
tail -f /var/log/hookprobe/vpn.log

# HTP tunnel logs
tail -f /var/log/hookprobe/htp.log
```

---

## Related Documentation

- **[SDN & VLAN Segmentation](SDN.md)** — Network segmentation for IoT devices
- **[Guardian Setup](../../install/guardian/README.md)** — Edge device deployment
- **[HTP Protocol](../architecture/hookprobe-neuro-protocol.md)** — Transport protocol details
- **[IAM Integration](../IAM-INTEGRATION-GUIDE.md)** — LogMe2 SSO setup

---

**HookProbe VPN** — *Your Network, Everywhere*

Version: 5.0.0 | MIT License
