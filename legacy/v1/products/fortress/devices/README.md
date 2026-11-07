# Fortress Device Profiles

This directory contains hardware-specific profiles for HookProbe Fortress. Each profile enables Fortress to automatically detect and configure network interfaces for specific device types.

## Supported Devices

| Device | Folder | Architecture | NICs | Status |
|--------|--------|--------------|------|--------|
| Intel N100/N150/N200/N305 Mini-PCs | `intel-n100/` | amd64 | 2-4x 2.5GbE | ✅ Tested |
| Raspberry Pi CM5 | `rpi-cm5/` | arm64 | 1-4x GbE | 🔄 In Development |
| Radxa Rock 5B | `radxa-rock5b/` | arm64 | 2.5GbE + GbE | 🔄 In Development |
| Template | `template/` | - | - | Reference |

### Status Legend
- ✅ Tested: Profile tested on real hardware
- 🔄 In Development: Profile created, needs hardware testing
- 📝 Planned: Profile planned but not yet created

## Quick Start

```bash
# Run hardware detection
source common/detect-hardware.sh
detect_hardware

# Check detected device
echo "Device: $FORTRESS_DEVICE_ID"
echo "Profile: $FORTRESS_PROFILE_DIR"

# Run device-specific interface detection
if [ -f "$FORTRESS_PROFILE_DIR/interfaces.sh" ]; then
    source "$FORTRESS_PROFILE_DIR/interfaces.sh"
    # Run the detection function (varies by device)
fi
```

## Directory Structure

```
devices/
├── README.md                    # This file
├── common/                      # Shared scripts
│   ├── detect-hardware.sh       # Hardware detection framework
│   └── lte-manager.sh           # LTE modem management
├── intel-n100/                  # Intel N100/N150/N200/N305
│   ├── profile.conf             # Device configuration
│   └── interfaces.sh            # Interface detection
├── rpi-cm5/                     # Raspberry Pi CM5
│   ├── profile.conf
│   └── interfaces.sh
├── radxa-rock5b/                # Radxa Rock 5B
│   ├── profile.conf
│   └── interfaces.sh
└── template/                    # Template for new devices
    ├── profile.conf
    └── interfaces.sh
```

## Adding a New Device Profile

1. **Copy the template**:
   ```bash
   cp -r template/ my-device-name/
   ```

2. **Edit `profile.conf`**:
   - Set `DEVICE_ID` to a unique identifier
   - Configure hardware capabilities
   - Set default interface assignments

3. **Edit `interfaces.sh`**:
   - Implement `detect_<device>_interfaces()` function
   - Add driver-specific detection logic
   - Configure XDP mode per interface

4. **Test the profile**:
   ```bash
   cd my-device-name/
   ./interfaces.sh
   ./interfaces.sh --generate /tmp/test.yaml
   ```

5. **Submit a pull request** to share with the community!

## Profile Components

### profile.conf

Device configuration file with:

| Section | Description |
|---------|-------------|
| Device Identification | DEVICE_ID, DEVICE_FAMILY, ARCHITECTURE |
| Hardware Capabilities | RAM, LAN ports, 2.5GbE support, PCIe |
| Network Interface Naming | Naming scheme, default assignments |
| WiFi/LTE Configuration | Chipset, slot types, recommended modems |
| QSecBit Tuning | CPU weight, XDP mode, energy monitoring |
| Container Resources | Memory limits, CPU allocation |

### interfaces.sh

Interface detection script that:

1. Detects all network interfaces (onboard, PCIe, USB)
2. Assigns WAN and LAN interfaces
3. Generates netplan configuration
4. Configures XDP mode per interface

**Exported Variables**:
- `FORTRESS_WAN_IFACE`: Primary WAN interface
- `FORTRESS_LAN_IFACES`: Space-separated LAN interfaces
- `FORTRESS_TOTAL_NICS`: Total number of NICs detected
- `FORTRESS_XDP_MODE_<iface>`: XDP mode per interface

## Common Scripts

### detect-hardware.sh

Main hardware detection framework that:
- Identifies device type (Intel, ARM, etc.)
- Selects appropriate device profile
- Sets up environment variables

**Detection Methods**:
- DMI/SMBIOS for Intel x86 systems
- Device tree for ARM SBCs
- CPU model parsing
- PCI device enumeration

### lte-manager.sh

LTE modem management with:
- USB LTE modem detection
- ModemManager integration
- APN configuration
- WAN failover setup
- Health monitoring

**Supported Modems**:
- Quectel: EC25, EM05, RM500Q
- Sierra Wireless: EM7455, EM7565
- Huawei: ME909s
- Fibocom: FM150, L850-GL

## Interface Assignment Strategies

### Intel Mini-PCs
- Sort interfaces by PCI bus address
- First port = WAN, remaining = LAN
- 2.5GbE i225/i226 NICs detected automatically

### ARM SBCs
- Device tree naming (eth0, eth1)
- PCIe NICs for additional ports
- USB NICs as fallback

### Dual-NIC Devices (Rock 5B)
- Faster interface (2.5GbE) = WAN
- Slower interface (1GbE) = LAN

## XDP Mode Support

| Driver | XDP Mode | Notes |
|--------|----------|-------|
| igc (Intel i225/i226) | native | Full hardware support |
| i40e (Intel 10GbE) | native | Full hardware support |
| r8125 (Realtek 2.5GbE) | native | Partial support |
| r8169 (Realtek GbE) | generic | Software fallback |
| bcmgenet (Broadcom) | generic | No hardware support |
| rk_gmac-dwmac (Rockchip) | generic | No hardware support |

## WAN Failover

The `lte-manager.sh` script provides automatic WAN failover:

```
Primary WAN (Ethernet)
        │
        │ Health Check Fails
        ▼
Backup WAN (LTE)
        │
        │ Primary Recovers
        ▼
Primary WAN (Ethernet)
```

**Configuration**:
```bash
# Set failover parameters
export HEALTH_CHECK_INTERVAL=30    # Check every 30s
export FAILOVER_THRESHOLD=3        # Fail after 3 checks
export FAILBACK_THRESHOLD=5        # Recover after 5 checks

# Start failover monitoring
monitor_wan_failover &
```

## Troubleshooting

### Device Not Detected

```bash
# Check DMI info (Intel)
cat /sys/class/dmi/id/product_name
cat /sys/class/dmi/id/sys_vendor

# Check device tree (ARM)
cat /proc/device-tree/model

# Check CPU
cat /proc/cpuinfo | grep "model name"
```

### Interface Not Found

```bash
# List all network interfaces
ls -la /sys/class/net/

# Check interface driver
ethtool -i eth0

# Check PCI devices
lspci | grep -i ethernet
```

### LTE Modem Issues

```bash
# Check USB devices
lsusb | grep -E "Quectel|Sierra|Huawei"

# Check ModemManager
mmcli -L
mmcli -m 0

# Check network interfaces
ip link show | grep wwan
```

## Contributing

We welcome contributions! To add support for a new device:

1. Create a device profile following the template
2. Test on real hardware
3. Document any quirks or special requirements
4. Submit a pull request

### Device Information to Include

- Device name and model number
- Manufacturer
- CPU/SoC specifications
- Network interface details
- PCIe/USB slot configuration
- Any known issues or limitations

## References

- [Intel i225/i226 NIC Documentation](https://www.intel.com/content/www/us/en/products/details/ethernet/gigabit-controllers.html)
- [Raspberry Pi CM5 Documentation](https://www.raspberrypi.com/documentation/computers/compute-module.html)
- [Radxa Rock 5B Wiki](https://wiki.radxa.com/Rock5/5b)
- [XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [ModemManager Documentation](https://www.freedesktop.org/software/ModemManager/man/1.0.0/mmcli.1.html)
