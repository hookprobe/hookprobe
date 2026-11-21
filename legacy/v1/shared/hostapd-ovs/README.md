# hostapd-ovs - OVS Bridge Support for hostapd

**Location**: `shared/hostapd-ovs/`
**Status**: Production Ready
**License**: AGPL-3.0

## Overview

This module provides a patched version of hostapd (2.10/2.11) that can directly bridge WiFi interfaces to Open vSwitch (OVS) bridges, eliminating the need for veth pairs and intermediate Linux bridges.

### The Problem

Standard hostapd uses sysfs (`/sys/class/net/<bridge>/brif/`) to detect bridge membership. This works for Linux bridges but **fails for OVS bridges** because OVS doesn't populate sysfs bridge interfaces.

**Before (workaround architecture):**
```
WiFi Interface → Linux Bridge (br-wifi) → veth pair → OVS Bridge (FTS)
                        ↑                      ↑
                   hostapd bridge=          OVS port
```

This requires:
- Extra Linux bridge per WiFi interface
- veth pair creation and management
- Complex cleanup during uninstall
- Potential MTU/performance issues

### The Solution

This patch adds an OVS fallback to hostapd's `linux_br_get()` function. When the standard sysfs lookup fails, it queries `ovs-vsctl port-to-br` to find the OVS bridge that owns the interface.

**After (direct OVS integration):**
```
WiFi Interface → OVS Bridge (FTS)
        ↑             ↑
   hostapd       OpenFlow rules
   bridge=FTS
```

Benefits:
- Direct OVS integration (no intermediate bridges)
- Simpler configuration
- Better performance (no veth overhead)
- Full OpenFlow policy control over WiFi traffic
- Cleaner network stack

## Installation

### Quick Install

```bash
# Build and install hostapd 2.11 with OVS support
sudo ./build-hostapd-ovs.sh

# Or specify version 2.10
sudo HOSTAPD_VERSION=2.10 ./build-hostapd-ovs.sh
```

### Check Installation

```bash
./build-hostapd-ovs.sh --check
```

### Uninstall

```bash
sudo ./build-hostapd-ovs.sh --uninstall
```

## Usage

### hostapd.conf Configuration

Point the `bridge=` directive directly to your OVS bridge:

```ini
# Interface configuration
interface=wlan0
driver=nl80211

# Direct OVS bridge - no intermediate Linux bridge needed!
bridge=FTS

# Security
ssid=HookProbe-Fortress
wpa=2
wpa_key_mgmt=WPA-PSK SAE
wpa_passphrase=your_password

# Recommended for OVS integration
ap_isolate=1   # All traffic goes through OVS for policy enforcement
```

### Starting hostapd-ovs

```bash
# Test configuration
sudo hostapd-ovs -dd /etc/hostapd/hostapd.conf

# Run in background with PID file
sudo hostapd-ovs -B -P /run/hostapd.pid /etc/hostapd/hostapd.conf
```

### systemd Service

Example systemd unit for Fortress:

```ini
[Unit]
Description=hostapd-ovs WiFi AP (2.4GHz)
After=network.target openvswitch-switch.service
Requires=openvswitch-switch.service

[Service]
Type=forking
PIDFile=/run/hostapd-24ghz.pid
ExecStartPre=/usr/bin/ovs-vsctl br-exists FTS
ExecStart=/usr/local/bin/hostapd-ovs -B -P /run/hostapd-24ghz.pid /etc/hostapd/hostapd-24ghz.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## OVS Integration

### Adding WiFi Interface to OVS

The interface is added to OVS automatically when hostapd-ovs starts with `bridge=FTS`. However, you can pre-configure:

```bash
# Add WiFi interface to OVS bridge
ovs-vsctl add-port FTS wlan0

# With VLAN tag (for segmentation)
ovs-vsctl add-port FTS wlan0 tag=100
```

### OpenFlow Rules for WiFi

With direct OVS integration, you have full OpenFlow control:

```bash
# Allow DHCP from WiFi interface
ovs-ofctl add-flow FTS "in_port=wlan0,udp,tp_src=68,tp_dst=67,actions=NORMAL"

# Block WiFi-to-WiFi direct communication (force through controller)
ovs-ofctl add-flow FTS "in_port=wlan0,dl_dst=ff:ff:ff:ff:ff:ff,actions=CONTROLLER"

# Apply NAC policy based on MAC (route to LAN port)
ovs-ofctl add-flow FTS "in_port=wlan0,dl_src=aa:bb:cc:dd:ee:ff,actions=NORMAL"
```

## Supported Versions

| hostapd Version | WiFi Standards | Notes |
|-----------------|----------------|-------|
| 2.10 | WiFi 5 (802.11ac), WiFi 6 (802.11ax) | Stable, widely tested |
| 2.11 | WiFi 5, WiFi 6, WiFi 7 (802.11be) | Latest features |

## Technical Details

### Patch Location

The patch modifies `src/drivers/linux_ioctl.c`:

1. Adds `#include <ctype.h>` for input validation
2. Adds `linux_br_get_ovs()` helper function
3. Modifies `linux_br_get()` to call OVS fallback before returning -1

### Security

The OVS helper validates interface names to prevent command injection:
- Only alphanumeric characters, hyphens, underscores, and dots allowed
- Length checked against IFNAMSIZ
- 1-second timeout on ovs-vsctl to prevent hangs

### Build Configuration

The following features are enabled:

| Feature | Config | Purpose |
|---------|--------|---------|
| nl80211 driver | CONFIG_DRIVER_NL80211 | Modern Linux WiFi |
| VLAN support | CONFIG_FULL_DYNAMIC_VLAN | Network segmentation |
| ACS | CONFIG_ACS | Auto channel selection |
| WPA3 | CONFIG_SAE, CONFIG_OWE | Modern security |
| WiFi 7 | CONFIG_IEEE80211BE | 802.11be (2.11 only) |

## Troubleshooting

### hostapd won't start

```bash
# Check OVS bridge exists
ovs-vsctl br-exists FTS && echo "Bridge exists" || echo "Bridge missing"

# Check interface is not already in use
ip link show wlan0

# Run with debug output
hostapd-ovs -dd /etc/hostapd/hostapd.conf
```

### Interface not added to OVS

```bash
# Check OVS port list
ovs-vsctl list-ports FTS

# Manually add interface
ovs-vsctl add-port FTS wlan0
```

### Permission errors

```bash
# hostapd-ovs needs to run as root
sudo hostapd-ovs ...

# Check ovs-vsctl is executable
which ovs-vsctl
ls -la /usr/bin/ovs-vsctl
```

## HookProbe Integration

### Fortress

Fortress uses hostapd-ovs for direct OVS WiFi integration:

```bash
# Install during Fortress setup
./install.sh  # Automatically builds hostapd-ovs

# Check status
systemctl status fts-hostapd-24ghz
systemctl status fts-hostapd-5ghz
```

### Guardian

Guardian can use hostapd-ovs for travel companion deployments:

```bash
# Enable OVS mode in Guardian
./scripts/setup.sh --ovs-wifi
```

## Files

| File | Purpose |
|------|---------|
| `build-hostapd-ovs.sh` | Build and install script |
| `README.md` | This documentation |

## References

- [hostapd source](https://w1.fi/hostapd/)
- [Open vSwitch documentation](https://www.openvswitch.org/)
- [HookProbe Fortress architecture](../../products/fortress/CONTAINER_ARCHITECTURE.md)
