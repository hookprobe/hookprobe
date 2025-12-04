# HookProbe Guardian

> **"Protection on the Move"** - Travel-secure gateway

## Overview

Guardian is a travel-secure router and home gateway that transforms single-board computers into powerful security appliances. Perfect for protecting networks at home, small businesses, and on the road.

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 3GB | 4GB |
| Storage | 16GB | 32GB |
| Network | 2 interfaces | 2+ interfaces |
| Internet | Required | Required |
| MSSP ID | Required | Required |

## Supported Platforms

- Raspberry Pi 4 (4GB/8GB)
- Raspberry Pi 5
- Radxa Rock Pi
- Banana Pi
- Orange Pi
- Pine64 devices
- Other ARM SBCs with dual NICs

## Features

### Security
- **QSecBit**: Quantum-resistant security layer
- **OpenFlow**: Software-defined networking
- **WAF**: Web Application Firewall
- **IDS/IPS**: Suricata/Zeek intrusion detection
- **Lite AI**: Lightweight threat detection

### Network
- DHCP server for LAN clients
- WiFi hotspot (if hardware supports)
- Ad blocking (optional)
- Traffic shaping
- VLAN support

### Management
- MSSP-managed signatures
- Remote configuration
- Health monitoring
- Automatic updates

## Installation

### Quick Install

```bash
sudo ./install.sh --tier guardian
```

### With Options

```bash
# Interactive installation with prompts
sudo ./install.sh --tier guardian

# You will be prompted for:
# - MSSP ID
# - WiFi SSID (if hotspot capable)
# - WiFi password
# - Ad blocking preference
```

## Network Configuration

Guardian requires at least 2 network interfaces:

### Option 1: Dual Ethernet
```
eth0 (WAN) --> Internet
eth1 (LAN) --> Protected network
```

### Option 2: Ethernet + WiFi
```
eth0 (WAN) --> Internet
wlan0 (LAN) --> WiFi hotspot for clients
```

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/hookprobe/guardian.conf` | Main configuration |
| `/etc/hookprobe/wifi.conf` | WiFi hotspot settings |
| `/etc/hookprobe/secrets/mssp-id` | MSSP identification |
| `/etc/hookprobe/adblock.conf` | Ad blocking rules |

## Service Management

```bash
# Start Guardian
sudo systemctl start hookprobe-guardian

# Stop Guardian
sudo systemctl stop hookprobe-guardian

# Check status
sudo systemctl status hookprobe-guardian

# View logs
sudo journalctl -u hookprobe-guardian -f
```

## WiFi Hotspot

If your device supports AP mode:

```bash
# Configuration in /etc/hookprobe/wifi.conf
WIFI_ENABLED=true
WIFI_SSID="HookProbe-Guardian"
WIFI_PASS="your-secure-password"
WIFI_BAND="5GHz"  # or "2.4GHz"
```

## Ad Blocking

Guardian can block ads at the DNS level:

```bash
# Enable ad blocking
hookprobe-ctl adblock enable

# Disable ad blocking
hookprobe-ctl adblock disable

# Whitelist a domain
hookprobe-ctl adblock whitelist example.com
```

## Ports Used

| Port | Service |
|------|---------|
| 53 | DNS (dnsmasq) |
| 80 | HTTP redirect |
| 443 | HTTPS proxy |
| 8080 | Management API |
| 8443 | Management UI |

## Upgrading to Fortress

If you need local monitoring and dashboards:

```bash
sudo ./install.sh --tier fortress
```

Note: Fortress requires 8GB+ RAM and 2+ ethernet ports.

## Troubleshooting

### No Internet on LAN
```bash
# Check NAT rules
sudo iptables -t nat -L -n -v

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
```

### WiFi Hotspot Not Working
```bash
# Check hostapd status
sudo systemctl status hostapd

# Check WiFi capabilities
iw list | grep -A 10 "Supported interface modes"
```

### MSSP Connection Issues
```bash
# Test connectivity
curl -v https://your-mssp.example.com/api/health

# Check MSSP ID
cat /etc/hookprobe/secrets/mssp-id
```
