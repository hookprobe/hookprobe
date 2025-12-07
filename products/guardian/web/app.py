#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Simple Flask app for on-device configuration.
Runs on http://192.168.4.1:8080

Version: 5.0.0

Changes in 5.0.0:
- Added L2-L7 OSI layer threat detection and reporting
- Added mobile network protection for hotel/public WiFi
- QSecBit integration with layer-specific metrics
- New Security tab with layer breakdown visualization
"""

import os
import subprocess
import json
import re
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template_string, request, redirect, flash, jsonify, send_file

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration paths
HOSTAPD_CONF = Path('/etc/hostapd/hostapd.conf')
WPA_SUPPLICANT_CONF = Path('/etc/wpa_supplicant/wpa_supplicant-wlan1.conf')
DNSMASQ_CONF = Path('/etc/dnsmasq.d/guardian.conf')
MODE_FILE = Path('/opt/hookprobe/guardian/mode.conf')
LOGO_FILE = Path('/opt/hookprobe/guardian/web/hookprobe-emblem.png')
NEURO_STATS = Path('/opt/hookprobe/guardian/neuro/stats.json')
QSECBIT_STATS = Path('/opt/hookprobe/guardian/data/stats.json')
QSECBIT_THREATS = Path('/opt/hookprobe/guardian/data/threats.json')
LAYER_STATS = Path('/opt/hookprobe/guardian/data/layer_stats.json')
MOBILE_PROTECTION = Path('/opt/hookprobe/guardian/data/mobile_protection_state.json')
OVS_CONFIG = Path('/etc/hookprobe/ovs-config.sh')


def run_command(cmd, timeout=30):
    """Run shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode == 0
    except Exception as e:
        return str(e), False


def get_mode():
    """Get current Guardian mode."""
    return 'guardian'


def scan_wifi():
    """Scan for available WiFi networks using iw dev scan."""
    import time
    networks = []

    # Try scanning with wlan0 first (primary interface), then wlan1
    for iface in ['wlan0', 'wlan1']:
        # Bring interface up first (needs sudo)
        run_command(f'sudo ip link set {iface} up 2>/dev/null')

        # Try scan with sudo - iw dev <iface> scan requires root privileges
        output, success = run_command(f'sudo iw dev {iface} scan 2>/dev/null', timeout=30)

        # Debug: Check if we got output
        if output and 'BSS' in output:
            current_network = None

            for line in output.split('\n'):
                # Check for new BSS entry (network)
                if line.startswith('BSS '):
                    # Save previous network if it has SSID
                    if current_network and current_network.get('ssid'):
                        networks.append(current_network)

                    # Start new network - extract BSSID
                    bssid_match = re.search(r'BSS ([0-9a-f:]+)', line)
                    current_network = {
                        'bssid': bssid_match.group(1) if bssid_match else '',
                        'ssid': '',
                        'signal': -100,
                        'channel': 0,
                        'frequency': '',
                        'security': 'Open'
                    }
                elif current_network is not None:
                    # Parse indented lines (network properties)
                    line = line.strip()

                    if line.startswith('SSID:'):
                        ssid = line.split(':', 1)[1].strip()
                        if ssid and not ssid.startswith('\\x'):
                            current_network['ssid'] = ssid
                    elif line.startswith('signal:'):
                        try:
                            # Format: "signal: -55.00 dBm"
                            sig_str = line.split(':', 1)[1].strip()
                            sig_val = sig_str.split()[0]  # Get "-55.00"
                            current_network['signal'] = int(float(sig_val))
                        except:
                            pass
                    elif line.startswith('freq:'):
                        try:
                            # Format: "freq: 2442.0"
                            freq_str = line.split(':', 1)[1].strip()
                            freq_val = float(freq_str)
                            current_network['frequency'] = str(int(freq_val))
                            # Calculate channel from frequency
                            if freq_val >= 2412 and freq_val <= 2484:
                                current_network['channel'] = int((freq_val - 2407) / 5)
                            elif freq_val >= 5180:
                                current_network['channel'] = int((freq_val - 5000) / 5)
                        except:
                            pass
                    elif line.startswith('DS Parameter set:'):
                        # Format: "DS Parameter set: channel 7"
                        try:
                            ch_match = re.search(r'channel\s+(\d+)', line)
                            if ch_match:
                                current_network['channel'] = int(ch_match.group(1))
                        except:
                            pass
                    elif line.startswith('RSN:'):
                        current_network['security'] = 'WPA2'
                    elif line.startswith('WPA:'):
                        if current_network['security'] == 'Open':
                            current_network['security'] = 'WPA'
                    elif 'WEP' in line:
                        if current_network['security'] == 'Open':
                            current_network['security'] = 'WEP'

            # Don't forget last network
            if current_network and current_network.get('ssid'):
                networks.append(current_network)

        # If we got networks, stop trying other interfaces
        if networks:
            break

    # Fallback: Try iwlist scan if iw didn't work (needs sudo)
    if not networks:
        for iface in ['wlan0', 'wlan1']:
            output, success = run_command(f'sudo iwlist {iface} scan 2>/dev/null', timeout=30)
            if success and output and 'ESSID' in output:
                current_signal = -70
                for line in output.split('\n'):
                    line = line.strip()
                    if 'Signal level=' in line:
                        try:
                            sig = re.search(r'Signal level[=:](-?\d+)', line)
                            if sig:
                                current_signal = int(sig.group(1))
                        except:
                            pass
                    elif 'ESSID:' in line:
                        match = re.search(r'ESSID:"([^"]*)"', line)
                        if match and match.group(1):
                            networks.append({
                                'ssid': match.group(1),
                                'signal': current_signal,
                                'channel': 0,
                                'security': 'Unknown'
                            })
                            current_signal = -70

            if networks:
                break

    # Remove duplicates and sort by signal
    seen = set()
    unique_networks = []
    for net in networks:
        if net['ssid'] not in seen:
            seen.add(net['ssid'])
            unique_networks.append(net)

    unique_networks.sort(key=lambda x: x['signal'], reverse=True)
    return unique_networks[:20]


def get_wireless_interfaces():
    """Discover all wireless interfaces on the system."""
    interfaces = []

    # Method 1: Check /sys/class/net for wireless interfaces
    output, success = run_command('ls -1 /sys/class/net/')
    if success and output:
        for iface in output.split('\n'):
            iface = iface.strip()
            if iface:
                # Check if it's a wireless interface
                wireless_path = f'/sys/class/net/{iface}/wireless'
                phy_path = f'/sys/class/net/{iface}/phy80211'
                check, _ = run_command(f'test -d {wireless_path} || test -d {phy_path} && echo yes')
                if 'yes' in check:
                    interfaces.append(iface)

    # Method 2: Fallback to iw dev
    if not interfaces:
        output, success = run_command('iw dev 2>/dev/null')
        if success and output:
            for line in output.split('\n'):
                if 'Interface' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        interfaces.append(parts[1])

    # Method 3: Final fallback - check common interface names
    if not interfaces:
        for iface in ['wlan0', 'wlan1', 'wlan2', 'wlp2s0', 'wlp3s0']:
            check, success = run_command(f'ip link show {iface} 2>/dev/null')
            if success and iface in check:
                interfaces.append(iface)

    return sorted(set(interfaces))


def get_hostapd_interface():
    """Get the interface configured in hostapd.conf."""
    if HOSTAPD_CONF.exists():
        try:
            content = HOSTAPD_CONF.read_text()
            for line in content.split('\n'):
                if line.startswith('interface='):
                    return line.split('=', 1)[1].strip()
        except:
            pass
    return None


def get_interface_info(iface):
    """Get detailed info about a WiFi interface."""
    info = {
        'interface': iface,
        'type': 'unknown',
        'role': 'unknown',  # 'hotspot' or 'upstream' or 'unknown'
        'ssid': None,
        'channel': None,
        'frequency': None,
        'signal': None,
        'tx_power': None,
        'mac': None,
        'connected': False,
        'is_builtin': False,  # True if built-in WiFi (vs USB dongle)
        'driver': None
    }

    # Check if interface exists
    check, success = run_command(f'ip link show {iface} 2>/dev/null')
    if not success or iface not in check:
        return info

    # Try to determine if built-in or USB dongle
    phy_output, _ = run_command(f'readlink /sys/class/net/{iface}/device 2>/dev/null')
    if phy_output:
        # USB devices typically have 'usb' in their path
        info['is_builtin'] = 'usb' not in phy_output.lower()

    # Get driver name
    driver_output, _ = run_command(f'readlink /sys/class/net/{iface}/device/driver 2>/dev/null')
    if driver_output:
        info['driver'] = driver_output.split('/')[-1]

    # Get interface info using iw dev
    output, success = run_command(f'iw dev {iface} info 2>/dev/null')
    if success and output:
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('type '):
                info['type'] = line.split('type ', 1)[1].strip()
            elif line.startswith('ssid '):
                info['ssid'] = line.split('ssid ', 1)[1].strip()
            elif line.startswith('channel '):
                try:
                    ch = line.split('channel ', 1)[1].split()[0]
                    info['channel'] = int(ch)
                except:
                    pass
            elif 'freq' in line.lower():
                try:
                    freq_match = re.search(r'(\d+)\s*MHz', line)
                    if freq_match:
                        info['frequency'] = f"{freq_match.group(1)} MHz"
                except:
                    pass
            elif line.startswith('txpower '):
                info['tx_power'] = line.split('txpower ', 1)[1].strip()
            elif line.startswith('addr '):
                info['mac'] = line.split('addr ', 1)[1].strip()

    # Determine role based on hostapd config
    hostapd_iface = get_hostapd_interface()
    if hostapd_iface == iface:
        info['role'] = 'hotspot'
    elif info['type'] == 'AP':
        info['role'] = 'hotspot'
    elif info['type'] == 'managed':
        info['role'] = 'upstream'

    # For AP mode - check if hostapd is running and interface has SSID
    if info['type'] == 'AP':
        info['connected'] = True  # AP is broadcasting
        # If SSID not in iw output, check hostapd config
        if not info['ssid']:
            if HOSTAPD_CONF.exists():
                try:
                    content = HOSTAPD_CONF.read_text()
                    for line in content.split('\n'):
                        if line.startswith('ssid='):
                            info['ssid'] = line.split('=', 1)[1].strip()
                            break
                except:
                    pass

    # For managed mode - check if connected to a network
    elif info['type'] == 'managed':
        link_output, _ = run_command(f'iw dev {iface} link 2>/dev/null')
        if link_output:
            if 'Connected to' in link_output or 'SSID:' in link_output:
                info['connected'] = True
                for line in link_output.split('\n'):
                    line = line.strip()
                    if line.startswith('signal:'):
                        try:
                            info['signal'] = line.split(':', 1)[1].strip()
                        except:
                            pass
                    elif line.startswith('SSID:'):
                        info['ssid'] = line.split(':', 1)[1].strip()
            elif 'Not connected' in link_output:
                info['connected'] = False
            else:
                info['connected'] = False
        else:
            info['connected'] = False

    return info


def get_current_config():
    """Read current configuration."""
    config = {
        'hotspot_ssid': 'HookProbe-Guardian',
        'hotspot_password': '',
        'upstream_ssid': '',
        'upstream_password': '',
        'bridge_lan': True,
        'mode': get_mode(),
    }

    if HOSTAPD_CONF.exists():
        content = HOSTAPD_CONF.read_text()
        for line in content.split('\n'):
            if line.startswith('ssid='):
                config['hotspot_ssid'] = line.split('=', 1)[1]
            elif line.startswith('wpa_passphrase='):
                config['hotspot_password'] = line.split('=', 1)[1]

    if WPA_SUPPLICANT_CONF.exists():
        content = WPA_SUPPLICANT_CONF.read_text()
        ssid_match = re.search(r'ssid="([^"]*)"', content)
        psk_match = re.search(r'psk="([^"]*)"', content)
        if ssid_match:
            config['upstream_ssid'] = ssid_match.group(1)
        if psk_match:
            config['upstream_password'] = psk_match.group(1)

    return config


def get_status():
    """Get current system status with dynamic interface detection.

    Network Topology:
    - WAN (upstream/internet): wlan0 (built-in, managed mode) or eth0
    - LAN (hotspot/clients): USB WiFi dongle (AP mode, broadcasts Guardian SSID)
    """
    status = {}

    # Discover all wireless interfaces dynamically
    wireless_ifaces = get_wireless_interfaces()
    status['wireless_interfaces'] = wireless_ifaces

    # Get info for all discovered interfaces
    all_interfaces = {}
    for iface in wireless_ifaces:
        all_interfaces[iface] = get_interface_info(iface)

    # Also check wlan0/wlan1 even if not discovered (fallback)
    for iface in ['wlan0', 'wlan1']:
        if iface not in all_interfaces:
            info = get_interface_info(iface)
            if info['type'] != 'unknown':
                all_interfaces[iface] = info

    status['all_interfaces'] = all_interfaces

    # Check eth0 status for WAN bridging
    eth0_info = {
        'interface': 'eth0',
        'connected': False,
        'ip': None,
        'carrier': False
    }
    eth0_carrier, _ = run_command('cat /sys/class/net/eth0/carrier 2>/dev/null')
    eth0_info['carrier'] = eth0_carrier.strip() == '1'
    eth0_ip, _ = run_command("ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}'")
    if eth0_ip:
        eth0_info['ip'] = eth0_ip.strip()
        eth0_info['connected'] = True
    status['eth0'] = eth0_info

    # Determine WAN and LAN interfaces
    # WAN = wlan0 (built-in) in managed mode, or eth0
    # LAN = USB dongle (for Guardian hotspot), regardless of current mode

    hostapd_iface = get_hostapd_interface()
    lan_interface = None  # USB dongle - broadcasts Guardian SSID
    wan_interface = None  # Built-in wlan0 - connects to upstream

    # Step 1: Find WAN interface (built-in wlan0 in managed mode)
    # wlan0 is typically the built-in WiFi used for upstream connection
    if 'wlan0' in all_interfaces:
        wlan0_info = all_interfaces['wlan0']
        if wlan0_info['type'] == 'managed' or wlan0_info['is_builtin']:
            wan_interface = wlan0_info.copy()
            wan_interface['role'] = 'wan'

    # Step 2: Find LAN interface (USB dongle for hotspot)
    # Any non-built-in interface (USB dongle) is used for LAN/hotspot
    for iface, info in all_interfaces.items():
        # Skip the WAN interface
        if wan_interface and iface == wan_interface['interface']:
            continue

        # USB dongle = LAN (for hotspot)
        if not info['is_builtin']:
            lan_interface = info.copy()
            lan_interface['role'] = 'lan'
            break

        # Or if hostapd is configured for this interface
        if hostapd_iface and iface == hostapd_iface:
            lan_interface = info.copy()
            lan_interface['role'] = 'lan'
            break

        # Or if it's in AP mode
        if info['type'] == 'AP':
            lan_interface = info.copy()
            lan_interface['role'] = 'lan'
            break

    # Step 3: Fallback - if no WAN WiFi found, check eth0
    if not wan_interface and eth0_info['connected']:
        wan_interface = {
            'interface': 'eth0',
            'type': 'wired',
            'role': 'wan',
            'ssid': None,
            'channel': None,
            'frequency': None,
            'signal': None,
            'tx_power': None,
            'mac': None,
            'connected': True,
            'is_builtin': True,
            'driver': 'ethernet'
        }

    # Step 4: If still no LAN, use any remaining interface
    if not lan_interface:
        for iface, info in all_interfaces.items():
            if wan_interface and iface == wan_interface['interface']:
                continue
            lan_interface = info.copy()
            lan_interface['role'] = 'lan'
            break

    # Create empty interface info if not found
    empty_interface = {
        'interface': 'none',
        'type': 'unknown',
        'role': 'unknown',
        'ssid': None,
        'channel': None,
        'frequency': None,
        'signal': None,
        'tx_power': None,
        'mac': None,
        'connected': False,
        'is_builtin': False,
        'driver': None
    }

    # Use WAN/LAN naming but keep legacy names for compatibility
    status['lan_interface'] = lan_interface or empty_interface
    status['wan_interface'] = wan_interface or empty_interface

    # Legacy compatibility (hotspot = LAN, upstream = WAN)
    status['hotspot_interface'] = status['lan_interface']
    status['upstream_interface'] = status['wan_interface']
    status['wlan0'] = all_interfaces.get('wlan0', empty_interface)
    status['wlan1'] = all_interfaces.get('wlan1', empty_interface)

    # Determine connection status
    status['wan_connected'] = (
        status['wan_interface']['type'] in ['managed', 'wired'] and
        status['wan_interface'].get('connected', False)
    )
    status['lan_active'] = status['lan_interface']['type'] == 'AP'

    # Legacy compatibility
    status['upstream_connected'] = status['wan_connected']
    status['hotspot_active'] = status['lan_active']

    output, _ = run_command('hostname -I')
    status['ip_addresses'] = output.split()

    output, _ = run_command('systemctl is-active hostapd')
    status['hostapd'] = output == 'active'

    output, _ = run_command('systemctl is-active dnsmasq')
    status['dnsmasq'] = output == 'active'

    # Get connected clients from LAN/AP interface
    ap_iface = status['lan_interface']['interface']
    if ap_iface and ap_iface != 'none':
        output, _ = run_command(f'iw dev {ap_iface} station dump 2>/dev/null | grep Station | wc -l')
        status['clients'] = int(output) if output.isdigit() else 0
    else:
        status['clients'] = 0

    status['mode'] = get_mode()

    # System info
    output, _ = run_command('uptime -p 2>/dev/null || uptime')
    status['uptime'] = output

    output, _ = run_command("free -m | awk '/Mem:/ {printf \"%.0f%%\", $3/$2*100}'")
    status['memory_usage'] = output

    output, _ = run_command("df -h / | awk 'NR==2 {print $5}'")
    status['disk_usage'] = output

    output, _ = run_command("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null")
    if output and output.isdigit():
        status['cpu_temp'] = f"{int(output) / 1000:.1f}°C"
    else:
        status['cpu_temp'] = 'N/A'

    return status


def get_container_status():
    """Get status of all security containers and services."""
    containers = {
        'suricata': {'name': 'guardian-suricata', 'label': 'Suricata IDS/IPS', 'running': False, 'type': 'container'},
        'zeek': {'name': 'guardian-zeek', 'label': 'Zeek Network Analysis', 'running': False, 'type': 'container'},
        'waf': {'name': 'guardian-waf', 'label': 'ModSecurity WAF', 'running': False, 'type': 'container'},
        'neuro': {'name': 'guardian-neuro', 'label': 'Neuro Protocol', 'running': False, 'type': 'container'},
        'adguard': {'name': 'guardian-adguard', 'label': 'AdGuard DNS', 'running': False, 'type': 'container'},
        'xdp': {'name': 'guardian-xdp', 'label': 'XDP DDoS Protection', 'running': False, 'type': 'service'},
        'aggregator': {'name': 'guardian-aggregator', 'label': 'Threat Aggregator', 'running': False, 'type': 'service'},
    }

    # Check podman containers
    output, _ = run_command('podman ps --format "{{.Names}}" 2>/dev/null')
    running = output.split('\n') if output else []

    for key, container in containers.items():
        if container['type'] == 'container':
            container['running'] = container['name'] in running
        # Check systemd service status
        svc_output, _ = run_command(f'systemctl is-active {container["name"]}')
        container['service_active'] = svc_output == 'active'
        if container['type'] == 'service':
            container['running'] = container['service_active']

    # Check XDP loaded on interface
    xdp_output, _ = run_command('ip link show | grep xdp')
    if xdp_output:
        containers['xdp']['running'] = True

    return containers


def get_qsecbit_data():
    """Get comprehensive QSecBit/Neuro security data with RAG status."""
    data = {
        'overall_status': 'green',  # RAG status
        'neuro': {
            'status': 'inactive',
            'mode': 'unknown',
            'timestamp': None,
            'rag': 'red'
        },
        'qsecbit': {
            'status': 'inactive',
            'connections': 0,
            'timestamp': None,
            'interfaces': {},
            'xdp_enabled': False,
            'ebpf_programs': [],
            'rag': 'red'
        },
        'energy': {
            'interfaces': {},
            'total_tx_bytes': 0,
            'total_rx_bytes': 0,
            'rag': 'green'
        },
        'threats': {
            'count': 0,
            'recent': [],
            'rag': 'green'
        },
        'suricata': {
            'alerts': [],
            'alert_count': 0,
            'rag': 'green'
        },
        'ovs': {
            'config': None,
            'bridges': None,
            'rag': 'amber'
        }
    }

    # Check XDP/eBPF status
    xdp_output, _ = run_command('ip link show | grep xdp 2>/dev/null')
    data['qsecbit']['xdp_enabled'] = bool(xdp_output)

    # Get eBPF programs
    ebpf_output, success = run_command('bpftool prog list 2>/dev/null | head -20')
    if success and ebpf_output:
        programs = []
        for line in ebpf_output.split('\n'):
            if line.strip() and ':' in line:
                programs.append(line.strip()[:60])
        data['qsecbit']['ebpf_programs'] = programs[:5]

    # Get interface energy/traffic stats
    for iface in ['wlan0', 'wlan1', 'br0', 'eth0']:
        stats = {}
        # TX bytes
        tx_output, _ = run_command(f'cat /sys/class/net/{iface}/statistics/tx_bytes 2>/dev/null')
        if tx_output and tx_output.isdigit():
            stats['tx_bytes'] = int(tx_output)
            data['energy']['total_tx_bytes'] += int(tx_output)
        # RX bytes
        rx_output, _ = run_command(f'cat /sys/class/net/{iface}/statistics/rx_bytes 2>/dev/null')
        if rx_output and rx_output.isdigit():
            stats['rx_bytes'] = int(rx_output)
            data['energy']['total_rx_bytes'] += int(rx_output)
        # TX packets
        tx_pkt, _ = run_command(f'cat /sys/class/net/{iface}/statistics/tx_packets 2>/dev/null')
        if tx_pkt and tx_pkt.isdigit():
            stats['tx_packets'] = int(tx_pkt)
        # RX packets
        rx_pkt, _ = run_command(f'cat /sys/class/net/{iface}/statistics/rx_packets 2>/dev/null')
        if rx_pkt and rx_pkt.isdigit():
            stats['rx_packets'] = int(rx_pkt)
        # TX errors
        tx_err, _ = run_command(f'cat /sys/class/net/{iface}/statistics/tx_errors 2>/dev/null')
        if tx_err and tx_err.isdigit():
            stats['tx_errors'] = int(tx_err)
        # RX errors
        rx_err, _ = run_command(f'cat /sys/class/net/{iface}/statistics/rx_errors 2>/dev/null')
        if rx_err and rx_err.isdigit():
            stats['rx_errors'] = int(rx_err)

        if stats:
            data['energy']['interfaces'][iface] = stats

    # Neuro stats
    if NEURO_STATS.exists():
        try:
            neuro = json.loads(NEURO_STATS.read_text())
            data['neuro']['status'] = neuro.get('status', 'unknown')
            data['neuro']['mode'] = neuro.get('mode', 'unknown')
            data['neuro']['timestamp'] = neuro.get('timestamp')
            data['neuro']['rag'] = 'green' if neuro.get('status') == 'active' else 'amber'
        except:
            pass

    # QSecBit stats (new v5.0 format from guardian_agent.py)
    if QSECBIT_STATS.exists():
        try:
            qsec = json.loads(QSECBIT_STATS.read_text())

            # Main QSecBit metrics
            data['qsecbit']['status'] = qsec.get('status', 'active')
            data['qsecbit']['score'] = qsec.get('score', 0.0)
            data['qsecbit']['timestamp'] = qsec.get('timestamp')
            data['qsecbit']['mode'] = qsec.get('mode', 'guardian-edge')
            data['qsecbit']['version'] = qsec.get('version', '5.0.0')

            # RAG from agent
            rag_status = qsec.get('rag_status', 'GREEN').lower()
            data['qsecbit']['rag'] = rag_status
            data['overall_status'] = rag_status  # Override overall status

            # Components (drift, attack_probability, classifier_decay, quantum_drift, energy_anomaly)
            components = qsec.get('components', {})
            data['qsecbit']['drift'] = components.get('drift', 0.0)
            data['qsecbit']['attack_probability'] = components.get('attack_probability', 0.0)
            data['qsecbit']['classifier_decay'] = components.get('classifier_decay', 0.0)
            data['qsecbit']['quantum_drift'] = components.get('quantum_drift', 0.0)
            data['qsecbit']['energy_anomaly'] = components.get('energy_anomaly', 0.0)

            # XDP stats from agent
            xdp_stats = qsec.get('xdp', {})
            data['qsecbit']['xdp_enabled'] = xdp_stats.get('xdp_enabled', False)
            data['qsecbit']['xdp_stats'] = xdp_stats

            # Energy stats from agent
            energy_stats = qsec.get('energy', {})
            data['qsecbit']['rapl_available'] = energy_stats.get('rapl_available', False)
            data['energy']['total_rx_bytes'] = energy_stats.get('total_rx_bytes', 0)
            data['energy']['total_tx_bytes'] = energy_stats.get('total_tx_bytes', 0)
            if 'interfaces' in energy_stats:
                data['energy']['interfaces'] = energy_stats['interfaces']

            # Network stats from agent
            network_stats = qsec.get('network', {})
            data['qsecbit']['connections'] = network_stats.get('connections', 0)
            data['qsecbit']['nic_info'] = network_stats.get('nic_info', {})

            # Threats and alerts counts from agent
            data['threats']['count'] = qsec.get('threats', 0)
            data['suricata']['alert_count'] = qsec.get('suricata_alerts', 0)

            # Update threat RAG based on count
            threat_count = qsec.get('threats', 0)
            if threat_count == 0:
                data['threats']['rag'] = 'green'
            elif threat_count < 5:
                data['threats']['rag'] = 'amber'
            else:
                data['threats']['rag'] = 'red'

            # Update Suricata RAG based on alert count
            alert_count = qsec.get('suricata_alerts', 0)
            if alert_count == 0:
                data['suricata']['rag'] = 'green'
            elif alert_count < 10:
                data['suricata']['rag'] = 'amber'
            else:
                data['suricata']['rag'] = 'red'

        except Exception as e:
            pass  # Fall back to defaults

    # Threats
    if QSECBIT_THREATS.exists():
        try:
            threats = []
            content = QSECBIT_THREATS.read_text().strip()
            if content:
                for line in content.split('\n')[-20:]:
                    if line:
                        threats.append(json.loads(line))
            data['threats']['recent'] = threats[-10:]
            data['threats']['count'] = len(threats)
            # RAG based on threat count
            if len(threats) == 0:
                data['threats']['rag'] = 'green'
            elif len(threats) < 5:
                data['threats']['rag'] = 'amber'
            else:
                data['threats']['rag'] = 'red'
        except:
            pass

    # Suricata alerts
    output, success = run_command('podman exec guardian-suricata tail -100 /var/log/suricata/eve.json 2>/dev/null')
    if success and output:
        alerts = []
        for line in output.split('\n'):
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    alerts.append({
                        'timestamp': event.get('timestamp', '')[:19],
                        'signature': event.get('alert', {}).get('signature', 'Unknown'),
                        'severity': event.get('alert', {}).get('severity', 0),
                        'src_ip': event.get('src_ip', ''),
                        'dest_ip': event.get('dest_ip', ''),
                        'category': event.get('alert', {}).get('category', ''),
                    })
            except:
                pass
        data['suricata']['alerts'] = alerts[-15:]
        data['suricata']['alert_count'] = len(alerts)
        # RAG based on severity
        high_sev = sum(1 for a in alerts if a.get('severity', 0) <= 2)
        if high_sev > 0:
            data['suricata']['rag'] = 'red'
        elif len(alerts) > 0:
            data['suricata']['rag'] = 'amber'
        else:
            data['suricata']['rag'] = 'green'

    # OVS config
    if OVS_CONFIG.exists():
        try:
            ovs_data = {}
            for line in OVS_CONFIG.read_text().split('\n'):
                if '=' in line and not line.startswith('#'):
                    key, val = line.split('=', 1)
                    ovs_data[key.strip()] = val.strip()
            data['ovs']['config'] = ovs_data
            data['ovs']['rag'] = 'green'
        except:
            pass

    output, _ = run_command('ovs-vsctl show 2>/dev/null')
    if output:
        data['ovs']['bridges'] = output
        data['ovs']['rag'] = 'green'

    # Calculate overall RAG
    rags = [data['neuro']['rag'], data['qsecbit']['rag'], data['threats']['rag'], data['suricata']['rag']]
    if 'red' in rags:
        data['overall_status'] = 'red'
    elif 'amber' in rags:
        data['overall_status'] = 'amber'
    else:
        data['overall_status'] = 'green'

    return data


def get_layer_threat_data():
    """Get L2-L7 layer threat breakdown data."""
    data = {
        'timestamp': None,
        'rag_status': 'green',
        'layers': {
            'L2_DATA_LINK': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0},
            'L3_NETWORK': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0},
            'L4_TRANSPORT': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0},
            'L5_SESSION': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0},
            'L6_PRESENTATION': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0},
            'L7_APPLICATION': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'blocked': 0},
        },
        'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'top_threat_types': {},
        'detection_coverage': {
            'L2_DATA_LINK': ['ARP Spoofing', 'MAC Flooding', 'Evil Twin', 'VLAN Hopping', 'Rogue DHCP'],
            'L3_NETWORK': ['IP Spoofing', 'ICMP Attacks', 'Routing Attacks', 'Fragmentation'],
            'L4_TRANSPORT': ['Port Scans', 'SYN Flood', 'TCP Anomalies', 'UDP Flood'],
            'L5_SESSION': ['SSL Attacks', 'Session Hijacking', 'Auth Bypass', 'Brute Force'],
            'L6_PRESENTATION': ['Encoding Attacks', 'Format Exploits', 'Crypto Attacks'],
            'L7_APPLICATION': ['Web Attacks', 'DNS Threats', 'Malware C2', 'Protocol Abuse']
        }
    }

    # Read layer stats file
    if LAYER_STATS.exists():
        try:
            layer_data = json.loads(LAYER_STATS.read_text())
            data['timestamp'] = layer_data.get('timestamp')
            data['rag_status'] = layer_data.get('rag_status', 'green')

            # Map layer data
            for layer_name, stats in layer_data.get('layers', {}).items():
                if layer_name in data['layers']:
                    data['layers'][layer_name] = {
                        'total': stats.get('total_threats', 0),
                        'critical': stats.get('critical', 0),
                        'high': stats.get('high', 0),
                        'medium': stats.get('medium', 0),
                        'low': stats.get('low', 0),
                        'blocked': stats.get('blocked', 0),
                        'threat_types': stats.get('threat_types', {})
                    }

            data['summary'] = layer_data.get('summary', data['summary'])
            data['top_threat_types'] = layer_data.get('top_threat_types', {})
        except Exception:
            pass

    # Calculate total if not present
    if data['summary']['total'] == 0:
        for layer_stats in data['layers'].values():
            data['summary']['total'] += layer_stats.get('total', 0)
            data['summary']['critical'] += layer_stats.get('critical', 0)
            data['summary']['high'] += layer_stats.get('high', 0)
            data['summary']['medium'] += layer_stats.get('medium', 0)
            data['summary']['low'] += layer_stats.get('low', 0)

    return data


def get_mobile_protection_data():
    """Get mobile network protection status for hotel/public WiFi."""
    data = {
        'status': 'inactive',
        'trust_level': 'UNKNOWN',
        'network_ssid': None,
        'vpn_active': False,
        'vpn_recommended': True,
        'protection_score': 0.0,
        'rag_status': 'amber',
        'anomalies': [],
        'security_checks': [],
        'captive_portal': 'NONE'
    }

    # Read mobile protection state
    if MOBILE_PROTECTION.exists():
        try:
            mobile_data = json.loads(MOBILE_PROTECTION.read_text())

            # Get known networks count
            data['known_networks_count'] = len(mobile_data.get('known_networks', {}))
            data['trusted_ssids'] = mobile_data.get('trusted_ssids', [])

            # Check if there's a current network in stats
            if QSECBIT_STATS.exists():
                qsec_data = json.loads(QSECBIT_STATS.read_text())
                mobile_stats = qsec_data.get('mobile_protection', {})
                if mobile_stats:
                    data['status'] = 'active'
                    data['trust_level'] = mobile_stats.get('trust_level', 'UNKNOWN')
                    data['network_ssid'] = mobile_stats.get('network_ssid')
                    data['vpn_active'] = mobile_stats.get('vpn_active', False)
                    data['protection_score'] = mobile_stats.get('protection_score', 0.0)
                    data['anomalies'] = mobile_stats.get('anomalies', [])

                    # Calculate RAG
                    score = data['protection_score']
                    if score >= 0.8:
                        data['rag_status'] = 'green'
                    elif score >= 0.5:
                        data['rag_status'] = 'amber'
                    else:
                        data['rag_status'] = 'red'

                    # VPN recommendation
                    data['vpn_recommended'] = data['trust_level'] in ['UNKNOWN', 'SUSPICIOUS', 'HOSTILE']

        except Exception:
            pass

    # Check VPN status
    output, success = run_command('ip link show wg0 2>/dev/null')
    if success and 'UP' in output:
        data['vpn_active'] = True

    return data


def get_connected_clients():
    """Get list of clients connected to the Guardian hotspot."""
    clients = []

    # Get the hostapd interface
    hostapd_iface = get_hostapd_interface()
    if not hostapd_iface:
        hostapd_iface = 'wlan1'  # Default fallback

    # Method 1: Get connected stations from hostapd_cli
    station_output, success = run_command(f'hostapd_cli -i {hostapd_iface} all_sta 2>/dev/null')
    connected_macs = set()

    if success and station_output:
        current_mac = None
        current_info = {}
        for line in station_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            # MAC address line (starts with hex)
            if len(line) == 17 and line.count(':') == 5:
                if current_mac:
                    connected_macs.add(current_mac)
                current_mac = line.lower()
                current_info = {'mac': current_mac, 'connected_time': 'Connected'}
            elif '=' in line and current_mac:
                key, value = line.split('=', 1)
                if key == 'connected_time':
                    # Convert seconds to human readable
                    try:
                        secs = int(value)
                        if secs < 60:
                            current_info['connected_time'] = f'{secs}s'
                        elif secs < 3600:
                            current_info['connected_time'] = f'{secs // 60}m {secs % 60}s'
                        else:
                            current_info['connected_time'] = f'{secs // 3600}h {(secs % 3600) // 60}m'
                    except:
                        pass

        if current_mac:
            connected_macs.add(current_mac)

    # Method 2: Get DHCP leases for IP and hostname info
    lease_output, _ = run_command('cat /var/lib/misc/dnsmasq.leases 2>/dev/null')
    lease_info = {}

    if lease_output:
        for line in lease_output.strip().split('\n'):
            if line:
                parts = line.split()
                if len(parts) >= 4:
                    mac = parts[1].lower()
                    lease_info[mac] = {
                        'ip': parts[2],
                        'hostname': parts[3] if parts[3] != '*' else '',
                        'name': parts[4] if len(parts) > 4 and parts[4] != '*' else ''
                    }

    # Combine information - prioritize connected stations from hostapd
    for mac in connected_macs:
        client = {
            'mac': mac,
            'ip': lease_info.get(mac, {}).get('ip', 'N/A'),
            'hostname': lease_info.get(mac, {}).get('hostname', ''),
            'name': lease_info.get(mac, {}).get('name', ''),
            'connected_time': 'Connected'
        }
        clients.append(client)

    # If hostapd_cli didn't return stations, fall back to DHCP leases
    if not clients and lease_info:
        for mac, info in lease_info.items():
            clients.append({
                'mac': mac,
                'ip': info.get('ip', 'N/A'),
                'hostname': info.get('hostname', ''),
                'name': info.get('name', ''),
                'connected_time': 'DHCP Lease'
            })

    return clients


def get_vpn_stats():
    """Get HTP file transfer statistics."""
    stats = {
        'connected': False,
        'mssp_host': 'mssp.hookprobe.com',
        'tunnel_state': 'disconnected',
        'htp_session': False,
        'rx_bytes': 0,
        'tx_bytes': 0,
        'rx_packets': 0,
        'tx_packets': 0,
        'last_activity': None,
        'uptime': None,
        'allowed_paths': ['/home', '/srv/files', '/var/log/guardian'],
        'active_transfers': 0,
        'file_transfers': [],
        'protocol': 'HTP',  # Using HTP instead of WebSocket
    }

    # Check if HTP service is running
    service_output, success = run_command('systemctl is-active guardian-htp 2>/dev/null')
    if success and service_output.strip() == 'active':
        stats['connected'] = True
        stats['tunnel_state'] = 'connected'
        stats['htp_session'] = True

    # Get HTP file transfer state file if exists
    htp_state_file = Path('/opt/hookprobe/guardian/data/htp_file_state.json')
    if htp_state_file.exists():
        try:
            with open(htp_state_file) as f:
                htp_state = json.load(f)
                stats.update({
                    'connected': htp_state.get('connected', False),
                    'tunnel_state': htp_state.get('state', 'disconnected'),
                    'htp_session': htp_state.get('session_active', False),
                    'rx_bytes': htp_state.get('bytes_received', 0),
                    'tx_bytes': htp_state.get('bytes_sent', 0),
                    'rx_packets': htp_state.get('packets_received', 0),
                    'tx_packets': htp_state.get('packets_sent', 0),
                    'last_activity': htp_state.get('last_activity'),
                    'uptime': htp_state.get('uptime'),
                    'active_transfers': htp_state.get('active_transfers', 0),
                    'file_transfers': htp_state.get('recent_transfers', [])[:10],
                })
        except:
            pass

    # Try to get config from guardian.yaml
    config_file = Path('/etc/guardian/guardian.yaml')
    if config_file.exists():
        try:
            import yaml
            with open(config_file) as f:
                config = yaml.safe_load(f)
                if config and 'htp_file' in config:
                    htp_config = config['htp_file']
                    stats['allowed_paths'] = htp_config.get('allowed_paths', stats['allowed_paths'])
                if config and 'htp' in config:
                    stats['mssp_host'] = config['htp'].get('mssp_host', stats['mssp_host'])
        except:
            pass

    return stats


# HTML Template with Tabs - Reorganized
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HookProbe Guardian - Protection on the Move</title>
    <style>
        :root {
            --hp-primary: #F05B2D;
            --hp-primary-dark: #d94d22;
            --hp-green: #10b981;
            --hp-amber: #f59e0b;
            --hp-red: #8E1529;
            --hp-dark: #0E162F;
            --hp-light: #FEFDFF;
            --hp-border: #e5e7eb;
            --hp-highlight: #F05B2D;
            --hp-warning: #8E1529;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--hp-light);
            min-height: 100vh;
        }

        .header {
            background: linear-gradient(135deg, var(--hp-dark) 0%, #1a2847 100%);
            color: #FEFDFF;
            padding: 25px 20px;
            text-align: center;
        }
        .header-content {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            flex-wrap: wrap;
        }
        .header-logo {
            width: 120px;
            height: 120px;
        }
        .header-logo img {
            width: 100%;
            height: 100%;
            object-fit: contain;
        }
        .header-text {
            text-align: left;
        }
        .header h1 {
            font-size: 26px;
            margin-bottom: 4px;
            color: #FEFDFF;
        }
        .header .tagline {
            font-size: 16px;
            font-weight: 600;
            color: var(--hp-highlight);
            margin-bottom: 2px;
        }
        .header .subtitle {
            font-size: 13px;
            opacity: 0.85;
            color: #FEFDFF;
        }
        .mode-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            margin-top: 10px;
        }
        .mode-guardian { background: var(--hp-green); }

        /* Tabs */
        .tabs {
            display: flex;
            justify-content: center;
            background: white;
            border-bottom: 1px solid var(--hp-border);
            overflow-x: auto;
        }
        .tab {
            padding: 15px 20px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            font-weight: 500;
            color: #6b7280;
            white-space: nowrap;
            transition: all 0.2s;
        }
        .tab:hover { color: var(--hp-primary); background: var(--hp-light); }
        .tab.active {
            color: var(--hp-primary);
            border-bottom-color: var(--hp-primary);
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        .container { max-width: 900px; margin: 0 auto; padding: 20px; }

        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid var(--hp-border);
        }
        .card h2 {
            margin-bottom: 20px;
            color: var(--hp-dark);
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card h2::before {
            content: '';
            width: 4px;
            height: 20px;
            background: var(--hp-primary);
            border-radius: 2px;
        }
        .card h3 {
            margin: 20px 0 10px;
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* RAG Indicators */
        .rag-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14px;
        }
        .rag-green { background: #dcfce7; color: #166534; }
        .rag-amber { background: #fef3c7; color: #92400e; }
        .rag-red { background: #fee2e2; color: #991b1b; }
        .rag-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        .rag-green .rag-dot { background: #22c55e; }
        .rag-amber .rag-dot { background: #f59e0b; }
        .rag-red .rag-dot { background: #ef4444; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* RAG Summary Cards */
        .rag-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .rag-card {
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 2px solid;
        }
        .rag-card.green { background: #f0fdf4; border-color: #22c55e; }
        .rag-card.amber { background: #fffbeb; border-color: #f59e0b; }
        .rag-card.red { background: #fef2f2; border-color: #ef4444; }
        .rag-card .title { font-size: 12px; color: #6b7280; text-transform: uppercase; margin-bottom: 8px; }
        .rag-card .value { font-size: 24px; font-weight: 700; }
        .rag-card.green .value { color: #166534; }
        .rag-card.amber .value { color: #92400e; }
        .rag-card.red .value { color: #991b1b; }
        .rag-card .status { font-size: 13px; margin-top: 5px; }

        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
        }
        .status-item {
            text-align: center;
            padding: 20px 15px;
            background: var(--hp-light);
            border-radius: 8px;
        }
        .status-item .value {
            font-size: 28px;
            font-weight: 700;
            color: var(--hp-primary);
        }
        .status-item .label {
            font-size: 12px;
            color: #6b7280;
            margin-top: 5px;
            text-transform: uppercase;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
        }
        .badge-success { background: #dcfce7; color: #166534; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .badge-success::before { background: #22c55e; }
        .badge-danger::before { background: #ef4444; }
        .badge-warning::before { background: #f59e0b; }

        .form-group { margin-bottom: 16px; }
        .test-input-row {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .test-input-row input {
            flex: 1;
            min-width: 150px;
        }
        .test-input-row button {
            flex: 0 0 auto;
            white-space: nowrap;
        }
        @media (max-width: 480px) {
            .test-input-row {
                flex-direction: column;
            }
            .test-input-row input,
            .test-input-row button {
                width: 100%;
            }
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-weight: 500;
            color: var(--hp-dark);
            font-size: 14px;
        }
        input, select {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--hp-border);
            border-radius: 8px;
            font-size: 15px;
        }
        input:focus, select:focus {
            outline: none;
            border-color: var(--hp-primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--hp-primary); color: white; }
        .btn-primary:hover { background: var(--hp-primary-dark); }
        .btn-secondary { background: #6b7280; color: white; }
        .btn-success { background: var(--hp-green); color: white; }
        .btn-danger { background: var(--hp-red); color: white; }
        .btn-sm { padding: 8px 16px; font-size: 13px; }
        .btn-group { display: flex; gap: 10px; flex-wrap: wrap; }

        /* Networks List */
        .networks {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid var(--hp-border);
            border-radius: 8px;
            margin-top: 15px;
        }
        .network-item {
            padding: 12px 15px;
            border-bottom: 1px solid var(--hp-border);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .network-item:last-child { border-bottom: none; }
        .network-item:hover { background: var(--hp-light); }
        .network-item .ssid { font-weight: 500; }
        .network-item .signal {
            font-size: 12px;
            color: #6b7280;
            padding: 4px 8px;
            background: var(--hp-light);
            border-radius: 4px;
        }

        /* Data Table - Responsive */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        .data-table th, .data-table td {
            padding: 8px 10px;
            text-align: left;
            border-bottom: 1px solid var(--hp-border);
            white-space: nowrap;
        }
        .data-table th {
            background: var(--hp-light);
            font-weight: 600;
            color: var(--hp-dark);
            font-size: 11px;
            text-transform: uppercase;
        }
        .data-table tr:hover { background: #f9fafb; }

        /* Device/Client Table - Responsive with smaller font */
        .device-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11px;
        }
        .device-table th, .device-table td {
            padding: 6px 8px;
            text-align: left;
            border-bottom: 1px solid var(--hp-border);
        }
        .device-table th {
            background: var(--hp-light);
            font-weight: 600;
            color: var(--hp-dark);
            font-size: 10px;
            text-transform: uppercase;
        }
        .device-table tr:hover { background: #f9fafb; }
        .device-table code {
            font-size: 10px;
            padding: 2px 4px;
            background: #f3f4f6;
            border-radius: 3px;
        }

        /* Table wrapper for horizontal scroll on mobile */
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            margin-bottom: 1rem;
        }

        /* Container Status */
        .container-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .container-item {
            padding: 15px;
            background: var(--hp-light);
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .container-item .name { font-weight: 500; }

        /* Alert List */
        .alert-list {
            max-height: 400px;
            overflow-y: auto;
        }
        .alert-item {
            padding: 12px;
            border-bottom: 1px solid var(--hp-border);
            font-size: 13px;
        }
        .alert-item:last-child { border-bottom: none; }
        .alert-item .signature { font-weight: 500; }
        .alert-item.sev-high .signature { color: var(--hp-red); }
        .alert-item.sev-medium .signature { color: var(--hp-amber); }
        .alert-item.sev-low .signature { color: var(--hp-green); }
        .alert-item .meta { color: #6b7280; font-size: 12px; margin-top: 4px; }

        /* Param Grid */
        .param-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }
        .param-item {
            padding: 12px;
            background: var(--hp-light);
            border-radius: 8px;
        }
        .param-item .label { font-size: 11px; color: #6b7280; text-transform: uppercase; }
        .param-item .value { font-size: 16px; font-weight: 600; color: var(--hp-dark); margin-top: 4px; }

        .flash {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .flash-success { background: #dcfce7; color: #166534; }
        .flash-error { background: #fee2e2; color: #991b1b; }

        .section-divider {
            border-top: 1px solid var(--hp-border);
            margin: 25px 0;
            padding-top: 25px;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #6b7280;
            font-size: 12px;
        }
        .footer a { color: var(--hp-primary); text-decoration: none; }

        @media (max-width: 768px) {
            .data-table { font-size: 11px; }
            .data-table th, .data-table td { padding: 6px 8px; }
            .data-table th { font-size: 10px; }
            .device-table { font-size: 10px; }
            .device-table th, .device-table td { padding: 5px 6px; }
            .device-table code { font-size: 9px; }
            .param-grid { grid-template-columns: repeat(2, 1fr); }
        }

        @media (max-width: 600px) {
            .tabs { flex-wrap: nowrap; overflow-x: auto; }
            .tab { padding: 12px 15px; font-size: 14px; white-space: nowrap; }
            .status-grid { grid-template-columns: repeat(2, 1fr); }
            .rag-grid { grid-template-columns: repeat(2, 1fr); }
            .btn-group { flex-direction: column; }
            .btn { width: 100%; }
            .data-table { font-size: 10px; }
            .data-table th, .data-table td { padding: 5px 6px; }
            .device-table { font-size: 9px; }
            .device-table th, .device-table td { padding: 4px 5px; }
            .device-table code { font-size: 8px; padding: 1px 3px; }
            .container-grid { grid-template-columns: 1fr; }
            .param-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="header-logo">
                <!-- HookProbe Emblem Logo -->
                <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjEiIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiB2aWV3Qm94PSIwIDAgODYwIDEwODAiIHhtbDpzcGFjZT0icHJlc2VydmUiPgo8ZyB0cmFuc2Zvcm09Im1hdHJpeCgxIDAgMCAxIDU0MCA1NDApIiA+CjxnIHN0eWxlPSIiIHZlY3Rvci1lZmZlY3Q9Im5vbi1zY2FsaW5nLXN0cm9rZSIgPgo8ZyB0cmFuc2Zvcm09Im1hdHJpeCgxIDAgMCAxIC0xMDQuMjkgMCkiID4KPHBhdGggc3R5bGU9InN0cm9rZTogbm9uZTsgc3Ryb2tlLXdpZHRoOiAxOyBzdHJva2UtZGFzaGFycmF5OiBub25lOyBzdHJva2UtbGluZWNhcDogcm91bmQ7IHN0cm9rZS1kYXNob2Zmc2V0OiAwOyBzdHJva2UtbGluZWpvaW46IHJvdW5kOyBzdHJva2UtbWl0ZXJsaW1pdDogMTA7IGZpbGw6IHJnYigyNTUsMjU1LDI1NSk7IGZpbGwtcnVsZTogbm9uemVybzsgb3BhY2l0eTogMTsiIHZlY3Rvci1lZmZlY3Q9Im5vbi1zY2FsaW5nLXN0cm9rZSIgdHJhbnNmb3JtPSIgdHJhbnNsYXRlKC0xMzkzLjksIC0zMzUuMTEpIiBkPSJNIDE1NzkuNTcgOTIuNzc2MSBDIDE1OTUuOTcgMTIxLjk4NCAxNjEyLjA0IDE1MC4zNzQgMTYyNy42OCAxNzguOTk3IEMgMTYzMS42MyAxODYuMzQ5IDE2MzcuMTcgMTkyLjcyNyAxNjQzLjg5IDE5Ny42NjUgQyAxNjY4LjI4IDIxNS43NzcgMTY4MC44MyAyNDAuNDUyIDE2NzkuOTcgMjcwLjU3OSBDIDE2NzguNSAzMjEuODU3IDE2NzkuMjIgMzczLjE5NiAxNjc1Ljc5IDQyNC40MTMgQyAxNjczLjk4IDQ1MS4zMDkgMTY2MC44OSA0NzEuODI1IDE2MzkuMzUgNDg3LjExIEMgMTYzMy40OSA0OTEuMTYxIDE2MjguNTggNDk2LjQzIDE2MjQuOTQgNTAyLjU1NyBDIDE2MTAuNSA1MjYuODI4IDE1OTUuNDIgNTUwLjcyNiAxNTgxLjE3IDU3NS4xMDggQyAxNTY4IDU5Ny42NjMgMTU0OC45OCA2MDcuOTQxIDE1MjIuODYgNjA2LjY5OSBDIDE0OTQuMjYgNjA1LjMzNiAxNDY1LjYxIDYwNS4wMTMgMTQzNi45OCA2MDQuMTQ1IEMgMTQzMC40OCA2MDMuOTQzIDE0MjQuNjQgNjA1LjQyNyAxNDE4LjYzIDYwOC4xNDMgQyAxMzkwLjMyIDYyMC45NTUgMTM2Mi4wMSA2MjAuNDcgMTMzNS4wNyA2MDQuODExIEMgMTI5MS43MSA1NzkuNjU0IDEyNDguNjcgNTUzLjk1NCAxMjA1Ljk2IDUyNy43MTcgQyAxMTgxLjEzIDUxMi40NDEgMTE2Ni43NyA0ODkuODU2IDExNjUuMTQgNDYwLjA4MyBDIDExNjQuODEgNDU0LjAyNSAxMTYyLjg4IDQ0OC41MTMgMTE1OS45MSA0NDMuMTYyIEMgMTE0NS43OSA0MTcuNzggMTEzMi4zNSAzOTIuMDE1IDExMTcuOCAzNjYuODk2IEMgMTEwNC43NSAzNDQuNDEyIDExMDQuMDEgMzIyLjgyNiAxMTE4LjIyIDMwMC42NjUgQyAxMTI5LjYgMjgyLjkxNiAxMTM5LjY1IDI2NC4yOTkgMTE1MS40MiAyNDYuODIzIEMgMTE2MC45OSAyMzIuNTk3IDExNjYuNDQgMjE3LjgxNyAxMTY3Ljg3IDIwMC41NjIgQyAxMTcwLjE4IDE3Mi42MjYgMTE4NC4zIDE1MC44MzkgMTIwOC41OSAxMzYuNzY1IEMgMTI1NC4wMiAxMTAuNDI0IDEyOTkuOTggODQuOTUxNiAxMzQ3LjE0IDYxLjgzMTUgQyAxMzczLjAzIDQ5LjE1MDcgMTM5OS42NSA1MC41MzM5IDE0MjUuMyA2My40NzcxIEMgMTQzMS42NSA2Ni43MDQ1IDE0MzguNyA2OC4zMzMzIDE0NDUuODIgNjguMjIyMyBDIDE0NzQuNDcgNjguMjEyMiAxNTAzLjEyIDY4LjQ3NDcgMTUzMS43OCA2OC43MDY5IEMgMTU1MS4yOCA2OC44Njg0IDE1NjcuMzYgNzYuMDk3MyAxNTc5LjU3IDkyLjc3NjEgTSAxNDMwLjAzIDQyMC42NDggQyAxNDE0LjYzIDQ0NS4yNTIgMTM5OS4zNiA0NjkuOTE3IDEzODMuODEgNDk0LjQyIEMgMTM3NS4wNSA1MDguMjExIDEzNzQuNTEgNTIxLjgwMSAxMzgyLjk4IDUzNS44OTUgQyAxMzg4LjEgNTQ0LjQwNiAxMzkzLjIgNTUyLjk5OCAxMzk3LjQ4IDU2MS45NDMgQyAxNDA0LjQ3IDU3Ni41MzIgMTQxNi40MiA1ODMuMTc1IDE0MzEuNzcgNTgzLjc1IEMgMTQ2NC4zMyA1ODQuOTgyIDE0OTYuOTIgNTg1LjU5OCAxNTI5LjUgNTg2LjQ0NiBDIDE1NDQuMDIgNTg2LjgyIDE1NTQuNjYgNTgwLjAzNSAxNTYyLjA2IDU2OC4wMTEgQyAxNTc0LjE0IDU0OC4zODQgMTU4Ni4wMiA1MjguNjE1IDE1OTcuOTMgNTA4Ljg2NyBDIDE2MjMuMzggNDY2LjYxNSAxNjI0Ljk0IDQ3Mi40MiAxNTk3LjAzIDQyMS44NzkgQyAxNTg4LjEyIDQwNS43NTYgMTU3NC44NiAzOTkuMDgyIDE1NTcgMzk5LjA2MiBDIDE1MjcuNTggMzk5LjAzMiAxNDk4LjE2IDM5OC41MTcgMTQ2OC43NCAzOTguMjg1IEMgMTQ2Ni4xMyAzOTguMjY0IDE0NjMuMDUgMzk3LjI2NSAxNDYwLjk5IDQwMC45NyBDIDE0NjUuMDggNDE0LjIzNyAxNDcyLjU0IDQyNi43MTUgMTQ3NS4wMyA0NDAuODcgQyAxNDc1LjYxIDQ0NC4yNDIgMTQ3Ny4zMSA0NDguMzIxIDE0NzMuMTEgNDUwLjUxMiBDIDE0NjkuMSA0NTIuNjEyIDE0NjYuMzQgNDQ5LjM3MSAxNDYzLjgyIDQ0Ny4wMDkgQyAxNDU1LjA4IDQzOC44MjEgMTQ0Ny41MyA0MjkuNTgzIDE0NDAuNjIgNDE5Ljg0IEMgMTQzNy4zMiA0MTUuMTg2IDE0MzQuNDQgNDEzLjY4MSAxNDMwLjAzIDQyMC42NDggTSAxNjA1LjAyIDIzOS4xNCBDIDE2MTkuODMgMjIwLjY2NCAxNjE5Ljc5IDIwMi4zOSAxNjA3LjI1IDE4Mi4xMDcgQyAxNTkyLjY0IDE1OC40NzIgMTU4MC4xMyAxMzMuNTQ0IDE1NjYuNzQgMTA5LjE2MiBDIDE1NTkuMTYgOTUuMzQwNSAxNTQ3LjY5IDg4LjcxNzQgMTUzMS43OSA4OC42NDY3IEMgMTUwMC43OSA4OC41MTU1IDE0NjkuOCA4Ny42Nzc1IDE0MzguNzkgODcuNDQ1MyBDIDE0MjIuNjMgODcuMzI0MiAxNDA5LjQzIDkzLjAwODMgMTQwMS4yMSAxMDguMDMxIEMgMTM5Ni4wOCAxMTcuNDMxIDEzOTAuMjggMTI2LjQ4NyAxMzg0LjY0IDEzNS42MTQgQyAxMzc2Ljc5IDE0OC4zMDUgMTM3Ni43MyAxNjAuOTY1IDEzODQuMTIgMTczLjg1OCBDIDEzOTkuMTQgMjAwLjA1NyAxNDE0LjA2IDIyNi4zMTcgMTQyOS4xMSAyNTIuNDk3IEMgMTQzMC44IDI1NS40MzUgMTQzMS45NSAyNTkuMjIxIDE0MzYuOCAyNTkuNjk1IEMgMTQ0NC40OCAyNTAuMzM2IDE0NTEuOTcgMjQwLjU4MyAxNDYwLjE2IDIzMS40NTYgQyAxNDY0LjE0IDIyNi45OTQgMTQ2OC43MSAyMTguOTQ3IDE0NzUuMTggMjIyLjY0MiBDIDE0ODEuNzEgMjI2LjM2OCAxNDc2LjYyIDIzNC4xNDIgMTQ3NS4yMiAyNDAuMDI4IEMgMTQ3Mi41OSAyNTEuMDYzIDE0NjUuNTEgMjYwLjY5NSAxNDY0LjIyIDI3Mi43NiBDIDE0NjcuMTMgMjczLjMxNSAxNDY5LjQgMjc0LjA4MiAxNDcxLjcgMjc0LjE0MyBDIDE1MDAuMyAyNzQuOTQgMTUyOC45IDI3NS40MzUgMTU1Ny40OSAyNzYuNDU1IEMgMTU3NC4yNiAyNzcuMDUgMTU4Ni43MSAyNzAuNzgxIDE1OTQuNzggMjU1Ljg2OSBDIDE1OTcuNiAyNTAuNjM5IDE2MDEuMDUgMjQ1LjczMiAxNjA1LjAyIDIzOS4xNCBNIDEzMjQuNjkgMzQ5LjUyIEMgMTMwNy4yMyAzNDYuNjMzIDEyODguNjggMzQ3LjQ4MSAxMjcxLjE4IDMzNS4zNDUgQyAxMjkwLjM0IDMyMi4xMiAxMzExLjcyIDMyNi43MTMgMTMzMS4xNCAzMTguNjI2IEMgMTMxMy44MSAyODguNjIxIDEyOTcuMiAyNTkuMjgxIDEyNzkuOTUgMjMwLjMyNiBDIDEyNzUuNTUgMjIyLjk0NSAxMjY3LjY3IDIxOC43MzUgMTI1OS4wMSAyMTcuOTE3IEMgMTI0NS41NiAyMTYuNjMyIDEyMzIuMDYgMjE1LjgzMSAxMjE4LjU1IDIxNS41MTUgQyAxMjAyLjI1IDIxNS4xNjEgMTE4OS41NCAyMjEuNTIyIDExODAuOSAyMzYuMTAxIEMgMTE2NS42OCAyNjEuNzY1IDExNDkuOTggMjg3LjE0NyAxMTM0LjI4IDMxMi41MDggQyAxMTI1LjY4IDMyNi40IDExMjUuNzUgMzQwLjE2MSAxMTMzLjUxIDM1NC4yNTUgQyAxMTQ4LjI4IDM4MS4xMDEgMTE2Mi45MyA0MDcuOTk3IDExNzcuNzIgNDM0LjgyMyBDIDExODUuMTEgNDQ4LjIzIDExOTYuOCA0NTQuNzEyIDEyMTEuOTIgNDU1LjAwNSBDIDEyMjQuMjUgNDU1LjIzNyAxMjM2LjYgNDU1LjAzNSAxMjQ4LjkyIDQ1NS4yNDcgQyAxMjYwLjYyIDQ1NS40NDkgMTI3MC41IDQ1MC44MjUgMTI3Ni42NiA0NDEuNDg2IEMgMTI5NC42MSA0MTQuMjU3IDEzMTEuNzEgMzg2LjQ3MiAxMzI5LjA5IDM1OC44NjkgQyAxMzMxLjUgMzU1LjAzMyAxMzMyLjQ0IDM1MS4zMzggMTMyNC42OSAzNDkuNTIgTSAxNDQ4LjI3IDMwMS41NzQgQyAxNDQ2LjQ5IDMwNi4xNTggMTQ0MS45MSAzMDkuODYzIDE0NDMuNzIgMzE2LjA0MiBDIDE0NDUuNjkgMzE2LjM3NSAxNDQ3LjYgMzE2LjkgMTQ0OS41MyAzMTcuMDAxIEMgMTQ3OC45IDMxOC40NjUgMTUwOC4yOSAzMTkuNjE2IDE1MzcuNjUgMzIxLjQwMyBDIDE1NTMuODkgMzIyLjM5MiAxNTcwLjAyIDMyNC44MjUgMTU4NS44NiAzMjguNjQyIEMgMTU5MC4yNSAzMjkuNjkyIDE1OTYuNjUgMzMwLjA5NSAxNTk2LjU0IDMzNi4xMDMgQyAxNTk2LjQ0IDM0MS45NTggMTU4OS45NCAzNDIuMTcgMTU4NS42NSAzNDMuNjA0IEMgMTU4MS4xIDM0NS4wNTUgMTU3Ni40MyAzNDYuMDU2IDE1NzEuNjkgMzQ2LjU5MyBDIDE1MzIuNjMgMzUxLjQyOSAxNDkzLjQ0IDM1NC4yODYgMTQ1NC4wNiAzNTMuOTUzIEMgMTQ0OS41MyAzNTMuOTIyIDE0NDQuNDggMzUyLjI5NyAxNDM5LjUxIDM1Ny4yNDQgQyAxNDQ1LjUxIDM2NC4yOTEgMTQ0Mi43OSAzNzguMTYzIDE0NTcuNjYgMzc4LjI5NCBDIDE0OTEuODMgMzc4LjU5NyAxNTI2LjAxIDM3OC42MDcgMTU2MC4xOCAzNzkuMjUzIEMgMTU4NC45NyAzNzkuNzE4IDE2MDMuMjcgMzkxLjE4NyAxNjE0Ljc0IDQxMy40NjkgQyAxNjIyLjY3IDQyOC45MDYgMTYzMi43MyA0NDMuMjYzIDE2MzcuNDUgNDYxLjM3NSBDIDE2NDcuMTQgNDUzLjk2NSAxNjUxLjI0IDQ0NC41MDUgMTY1NC4yMyA0MzQuODAyIEMgMTY1Ni40NyA0MjcuNTgyIDE2NTcuNTUgNDIwLjA1NiAxNjU3LjQ0IDQxMi41IEMgMTY1Ni42NCAzNjIuNzg3IDE2NjEuMzUgMzEzLjE0NCAxNjU5LjcyIDI2My40MjEgQyAxNjU5LjEyIDI0NS40MjkgMTY1MS43NiAyMzAuNTQ4IDE2MzYuOTggMjE3Ljc0NiBDIDE2MzEuMTQgMjM3LjU2NSAxNjE5Ljg5IDI1MS43MzkgMTYxMS4wNCAyNjcuMjA3IEMgMTU5OS41MyAyODcuMzU5IDE1ODIuMDkgMjk3LjA5MSAxNTU4Ljg4IDI5Ni41MTYgQyAxNTI3LjA4IDI5NS43MjggMTQ5NS4yOCAyOTQuOTYxIDE0NjMuNDkgMjk0LjE5NCBDIDE0NTcuODYgMjk0LjA1MiAxNDUyLjEyIDI5My42NjkgMTQ0OC4yNyAzMDEuNTc0IE0gMTI1MC44OCAxMzUuODM2IEMgMTIzNy4zNSAxNDQuMTQ1IDEyMjIuMTQgMTQ5LjcxOCAxMjEwIDE2MC4yNTkgQyAxMTk4LjE0IDE3MC41NTcgMTE4OS43IDE4Mi44NzQgMTE4OC4yNiAyMDAuODg1IEMgMTIwOS4zMyAxOTQuNDU0IDEyMjkuMjMgMTk3Ljg2NyAxMjQ4Ljk2IDE5Ny4xNiBDIDEyNzIuNzUgMTk2LjI5MiAxMjkwLjIzIDIwNi44NzIgMTMwMS45MiAyMjcuMjk3IEMgMTMxNy4zMyAyNTQuMjEzIDEzMzIuNjMgMjgxLjE5IDEzNDcuOTUgMzA4LjE1NyBDIDEzNTUuMDkgMzIwLjcxNiAxMzU4LjYgMzIxLjg0NyAxMzcyLjkxIDMxNS4zOTYgQyAxMzcwLjM1IDMxMC40NjkgMTM2Ny44OSAzMDUuNTMyIDEzNjUuMjUgMzAwLjY4NSBDIDEzNDYuNiAyNjYuNDYgMTMyNy43NSAyMzIuMzE1IDEzMTQuMDEgMTk1LjcyNiBDIDEzMTEuMjMgMTg4LjMxNiAxMzAzLjg5IDE3Ny41MDMgMTMxMS4zOCAxNzIuODI4IEMgMTMyMC40IDE2Ny4yMDUgMTMyNi4wMSAxNzkuNDExIDEzMzEuMiAxODUuNTkgQyAxMzU0LjUgMjEzLjQxNSAxMzczLjQ1IDI0NC4yODkgMTM5Mi42NSAyNzQuOTgxIEMgMTM5Ny42MSAyODIuOTI2IDE0MDAuNzcgMjkyLjE4NSAxNDEwLjQxIDMwMC41NjQgQyAxNDE0LjY4IDI5MC4zOTggMTQyNi4zOSAyODYuNTIxIDE0MTkuNTggMjc0LjUwNiBDIDE0MDIuMzIgMjQ0LjA3NyAxMzg0LjEzIDIxNC4xOTIgMTM2Ni44MiAxODMuODAzIEMgMTM1NS40MiAxNjMuODAyIDEzNTYuMDEgMTQzLjY3MSAxMzY4LjQxIDEyMy45ODMgQyAxMzc4LjYxIDEwNy43NTkgMTM4Ni40OCA4OS45Nzk0IDE0MDMuMzkgNzYuMTQ3OCBDIDEzODMuODcgNzIuNTAzMSAxMzY3LjcyIDcyLjg2NjUgMTM1Mi4xOSA4MS4yODY3IEMgMTMxOC45OSA5OS4yODgxIDEyODUuNjcgMTE3LjA4OCAxMjUwLjg4IDEzNS44MzYgTSAxMzA2LjUgNDMyLjM2OSBDIDEzMDQuMzggNDM1LjczMSAxMzAyLjA3IDQzOC45ODIgMTMwMC4xNiA0NDIuNDY1IEMgMTI4Ny4xOCA0NjYuMTgxIDEyNjcuMjggNDc2LjgyMiAxMjQwLjI3IDQ3NS42MzEgQyAxMjIyLjU1IDQ3NC44NTQgMTIwNC43IDQ3Ni4yNTcgMTE4Ni4zNyA0NzAuMDM4IEMgMTE5MC43MSA0ODYuODI4IDExOTguNzEgNDk5Ljc2MSAxMjExLjk4IDUwNy44NTggQyAxMjU3LjgxIDUzNS44MjIgMTMwMy45MyA1NjMuMjk2IDEzNTAuMzUgNTkwLjI3MiBDIDEzNjQuNzYgNTk4LjY0MiAxMzgwLjg4IDU5OC4xNzggMTM5OC44OCA1OTQuMzkyIEMgMTM4MS45MSA1NzkuNzMyIDEzNzUuMDggNTYxLjEwNSAxMzY1LjI5IDU0NC4zODYgQyAxMzUzIDUyMy4zNDUgMTM1NC41NiA1MDIuOTExIDEzNjcuNiA0ODIuNjA3IEMgMTM4My43NCA0NTcuNTA5IDEzOTkuNDEgNDMyLjEyNyAxNDE1LjIzIDQwNi44MzYgQyAxNDIzLjY2IDM5My4zNTggMTQyMi4xMiAzODcuMDU4IDE0MDcuMzEgMzc2LjYzOSBMIDE0MDAuNDkgMzg3LjU4MyBDIDEzNzguMzggNDIzIDEzNTYuOTYgNDU4LjkzMiAxMzI5LjIzIDQ5MC40MDIgQyAxMzI1LjExIDQ5NS4wNzYgMTMyMC4zNiA1MDQuMzI0IDEzMTMuNiA1MDAuMzA2IEMgMTMwNi4yNyA0OTUuOTU1IDEzMTEuOTIgNDg3LjEgMTMxNC4xOCA0ODAuOCBDIDEzMjQuODcgNDUwLjczNCAxMzM5LjY3IDQyMi41NDYgMTM1NC43MyAzOTQuNTA5IEMgMTM2MS44MiAzODEuMzIzIDEzNjkuMDggMzY4LjIxOCAxMzc2LjgzIDM1NC4wNTQgQyAxMzY3LjIgMzUyLjQ4OSAxMzU4Ljk3IDM0Ny4wMzcgMTM1Mi40NiAzNTcuNzc5IEMgMTMzNy42MyAzODIuMjYyIDEzMjIuNDYgNDA2LjU0MyAxMzA2LjUgNDMyLjM2OSBNIDE0MTUuMSAzMjEuNjQ1IEMgMTQxMC41MSAzMjcuMTA3IDE0MDUuNiAzMjguNTEgMTM5OS4zNiAzMjEuNTk1IEMgMTQwMi42OCAzMzEuOTk0IDEzOTcuMTUgMzM0Ljg5MSAxMzg4Ljc4IDMzNi4zNDUgQyAxMzk2LjgzIDMzOS4xNTIgMTQwMC42NyAzNDIuODc3IDEzOTguMjcgMzUyLjU5IEMgMTQwNS44OSAzNDYuNjkzIDE0MDQuNTkgMzQ3LjAwNiAxNDA4LjUxIDM0Ny4yMzkgQyAxNDEzLjA0IDM0OC4wODcgMTQxNS4wOSAzNTEuMTk2IDE0MTkuNyAzNTUuNDA2IEMgMTQxNy42MSAzNDUuOTQ2IDE0MTcuMjkgMzM5LjE2MiAxNDI4LjYxIDMzNi4xOTQgQyAxNDE1LjYxIDMzNi44MyAxNDE2Ljk3IDMyOC4wNDYgMTQxNS4xIDMyMS42NDUgWiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiAvPgo8L2c+CjwvZz4KPC9nPgo8L3N2Zz4=" alt="HookProbe" width="60" height="60">
            </div>
            <div class="header-text">
                <h1>HookProbe Guardian</h1>
                <div class="tagline">Protection on the Move</div>
                <div class="subtitle">Secure gateway with IDS/IPS, WAF, lite AI</div>
            </div>
        </div>
        <div class="mode-badge mode-guardian">
            Guardian Mode
        </div>
    </div>

    <!-- Tabs Navigation -->
    <div class="tabs">
        <div class="tab active" data-tab="dashboard">Dashboard</div>
        <div class="tab" data-tab="security">Security</div>
        <div class="tab" data-tab="clients">Clients</div>
        <div class="tab" data-tab="adguard">AdGuard</div>
        <div class="tab" data-tab="vpn">VPN</div>
        <div class="tab" data-tab="wifi">WiFi</div>
        <div class="tab" data-tab="system">System</div>
    </div>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
            <div class="flash flash-{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
        {% endwith %}

        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content active">
            <!-- Threat Distribution Chart - Top Priority -->
            <div class="card">
                <h2>Threat Distribution</h2>
                <div id="threat-chart" style="margin-bottom: 20px;">
                    <div style="display: flex; align-items: flex-end; height: 150px; gap: 20px; justify-content: center; padding: 20px 0;">
                        <!-- High Severity Bar -->
                        <div style="text-align: center; flex: 1; max-width: 120px;">
                            <div id="chart-bar-high" style="background: linear-gradient(to top, var(--hp-red), #dc2626); width: 100%; border-radius: 8px 8px 0 0; min-height: 10px; transition: height 0.5s ease;" data-height="10"></div>
                            <div style="background: #1f2937; color: white; padding: 8px; border-radius: 0 0 8px 8px;">
                                <div id="chart-value-high" style="font-size: 24px; font-weight: 700;">0</div>
                                <div style="font-size: 11px; text-transform: uppercase; opacity: 0.8;">High</div>
                            </div>
                        </div>
                        <!-- Medium Severity Bar -->
                        <div style="text-align: center; flex: 1; max-width: 120px;">
                            <div id="chart-bar-medium" style="background: linear-gradient(to top, var(--hp-amber), #fbbf24); width: 100%; border-radius: 8px 8px 0 0; min-height: 10px; transition: height 0.5s ease;" data-height="10"></div>
                            <div style="background: #1f2937; color: white; padding: 8px; border-radius: 0 0 8px 8px;">
                                <div id="chart-value-medium" style="font-size: 24px; font-weight: 700;">0</div>
                                <div style="font-size: 11px; text-transform: uppercase; opacity: 0.8;">Medium</div>
                            </div>
                        </div>
                        <!-- Low Severity Bar -->
                        <div style="text-align: center; flex: 1; max-width: 120px;">
                            <div id="chart-bar-low" style="background: linear-gradient(to top, var(--hp-green), #34d399); width: 100%; border-radius: 8px 8px 0 0; min-height: 10px; transition: height 0.5s ease;" data-height="10"></div>
                            <div style="background: #1f2937; color: white; padding: 8px; border-radius: 0 0 8px 8px;">
                                <div id="chart-value-low" style="font-size: 24px; font-weight: 700;">0</div>
                                <div style="font-size: 11px; text-transform: uppercase; opacity: 0.8;">Low</div>
                            </div>
                        </div>
                    </div>
                </div>
                <div style="text-align: center;">
                    <span id="chart-total" style="font-size: 14px; color: #6b7280;">Total Threats: <strong>0</strong></span>
                    <button type="button" class="btn btn-sm btn-secondary" onclick="refreshThreatChart()" style="margin-left: 15px;">Refresh</button>
                </div>
            </div>

            <div class="card">
                <h2>Security Overview</h2>
                <div class="rag-grid">
                    <div class="rag-card {{ qsecbit.overall_status }}">
                        <div class="title">Overall Status</div>
                        <div class="value">
                            {% if qsecbit.overall_status == 'green' %}SECURE
                            {% elif qsecbit.overall_status == 'amber' %}CAUTION
                            {% else %}ALERT{% endif %}
                        </div>
                        <div class="status">
                            {% if qsecbit.overall_status == 'green' %}All systems normal
                            {% elif qsecbit.overall_status == 'amber' %}Review recommended
                            {% else %}Immediate attention{% endif %}
                        </div>
                    </div>
                    <div class="rag-card {{ qsecbit.threats.rag }}">
                        <div class="title">Threats</div>
                        <div class="value">{{ qsecbit.threats.count }}</div>
                        <div class="status">Detected</div>
                    </div>
                    <div class="rag-card {{ qsecbit.suricata.rag }}">
                        <div class="title">IDS Alerts</div>
                        <div class="value">{{ qsecbit.suricata.alert_count }}</div>
                        <div class="status">Recent</div>
                    </div>
                    <div class="rag-card {{ qsecbit.neuro.rag }}">
                        <div class="title">Neuro Protocol</div>
                        <div class="value">{{ qsecbit.neuro.status | upper }}</div>
                        <div class="status">{{ qsecbit.neuro.mode }}</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Network Status</h2>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="value">{{ status.clients }}</div>
                        <div class="label">Connected Clients</div>
                    </div>
                    <div class="status-item">
                        <span class="badge {% if status.lan_active %}badge-success{% else %}badge-danger{% endif %}">
                            {% if status.lan_active %}Broadcasting{% else %}Stopped{% endif %}
                        </span>
                        <div class="label">LAN / Hotspot</div>
                        <div style="font-size: 11px; color: #6b7280; margin-top: 4px;">
                            {{ status.lan_interface.interface }} - {{ status.lan_interface.ssid or config.hotspot_ssid }}
                        </div>
                    </div>
                    <div class="status-item">
                        <span class="badge {% if status.wan_connected %}badge-success{% else %}badge-warning{% endif %}">
                            {% if status.wan_connected %}Connected{% else %}Disconnected{% endif %}
                        </span>
                        <div class="label">WAN / Internet</div>
                        <div style="font-size: 11px; color: #6b7280; margin-top: 4px;">
                            {% if status.wan_connected %}
                                {{ status.wan_interface.interface }} - {{ status.wan_interface.ssid or status.wan_interface.type | upper }}
                            {% else %}
                                {{ status.wan_interface.interface }} - Not connected
                            {% endif %}
                        </div>
                    </div>
                    <div class="status-item">
                        <span class="badge {% if status.dnsmasq %}badge-success{% else %}badge-danger{% endif %}">
                            {% if status.dnsmasq %}Running{% else %}Stopped{% endif %}
                        </span>
                        <div class="label">DHCP/DNS</div>
                    </div>
                </div>

                <!-- Interface Details -->
                <div style="margin-top: 15px; padding: 12px; background: var(--hp-light); border-radius: 8px; font-size: 13px;">
                    <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
                        <div>
                            <strong>LAN (Hotspot):</strong>
                            {{ status.lan_interface.interface }}
                            ({{ status.lan_interface.type | upper }})
                            {% if status.lan_interface.is_builtin %}- Built-in{% else %}- USB Dongle{% endif %}
                        </div>
                        <div>
                            <strong>WAN (Internet):</strong>
                            {{ status.wan_interface.interface }}
                            ({{ status.wan_interface.type | upper }})
                            {% if status.wan_interface.type == 'wired' %}- Ethernet{% elif status.wan_interface.is_builtin %}- Built-in{% else %}- USB{% endif %}
                        </div>
                        {% if status.eth0.carrier %}
                        <div>
                            <strong>eth0:</strong> Connected {% if status.eth0.ip %}({{ status.eth0.ip }}){% endif %}
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Security Containers</h2>
                <div class="container-grid">
                    {% for key, container in containers.items() %}
                    <div class="container-item">
                        <span class="name">{{ container.label }}</span>
                        <span class="badge {% if container.running %}badge-success{% else %}badge-danger{% endif %}">
                            {% if container.running %}Running{% else %}Stopped{% endif %}
                        </span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- Security Tab -->
        <div id="security" class="tab-content">
            <!-- Mobile Network Protection - For Hotels/Public WiFi -->
            <div class="card">
                <h2>Mobile Network Protection</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Protection status for hotel WiFi, airports, and public networks.
                </p>
                <div class="rag-grid">
                    <div class="rag-card {{ mobile_protection.rag_status }}">
                        <div class="title">Network Trust</div>
                        <div class="value">{{ mobile_protection.trust_level }}</div>
                        <div class="status">{{ mobile_protection.network_ssid or 'Not connected' }}</div>
                    </div>
                    <div class="rag-card {% if mobile_protection.vpn_active %}green{% else %}amber{% endif %}">
                        <div class="title">VPN Status</div>
                        <div class="value">{% if mobile_protection.vpn_active %}ACTIVE{% else %}INACTIVE{% endif %}</div>
                        <div class="status">{% if mobile_protection.vpn_recommended and not mobile_protection.vpn_active %}Recommended{% else %}OK{% endif %}</div>
                    </div>
                    <div class="rag-card {{ mobile_protection.rag_status }}">
                        <div class="title">Protection Score</div>
                        <div class="value">{{ "%.0f" | format(mobile_protection.protection_score * 100) }}%</div>
                        <div class="status">{{ mobile_protection.status | capitalize }}</div>
                    </div>
                </div>
                {% if mobile_protection.anomalies %}
                <div style="margin-top: 15px; padding: 12px; background: #fef2f2; border-radius: 8px; border-left: 4px solid var(--hp-red);">
                    <strong style="color: var(--hp-red);">Anomalies Detected:</strong>
                    <ul style="margin: 8px 0 0 20px; color: #991b1b;">
                        {% for anomaly in mobile_protection.anomalies %}
                        <li>{{ anomaly }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>

            <!-- L2-L7 Layer Threat Breakdown -->
            <div class="card">
                <h2>OSI Layer Threat Detection (L2-L7)</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Multi-layer threat detection across the OSI model for comprehensive protection.
                </p>

                <!-- Layer Breakdown Grid -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px;">
                    <!-- L2 Data Link -->
                    <div class="param-item" style="{% if layer_threats.layers.L2_DATA_LINK.critical > 0 %}background: #fee2e2; border-left: 4px solid var(--hp-red);{% elif layer_threats.layers.L2_DATA_LINK.high > 0 %}background: #fef3c7; border-left: 4px solid var(--hp-amber);{% else %}background: #d1fae5; border-left: 4px solid var(--hp-green);{% endif %}">
                        <div class="label">L2 Data Link</div>
                        <div class="value" id="layer-l2">{{ layer_threats.layers.L2_DATA_LINK.total }}</div>
                        <div style="font-size: 10px; color: #6b7280; margin-top: 4px;">ARP, MAC, VLAN</div>
                    </div>
                    <!-- L3 Network -->
                    <div class="param-item" style="{% if layer_threats.layers.L3_NETWORK.critical > 0 %}background: #fee2e2; border-left: 4px solid var(--hp-red);{% elif layer_threats.layers.L3_NETWORK.high > 0 %}background: #fef3c7; border-left: 4px solid var(--hp-amber);{% else %}background: #d1fae5; border-left: 4px solid var(--hp-green);{% endif %}">
                        <div class="label">L3 Network</div>
                        <div class="value" id="layer-l3">{{ layer_threats.layers.L3_NETWORK.total }}</div>
                        <div style="font-size: 10px; color: #6b7280; margin-top: 4px;">IP, ICMP, Routing</div>
                    </div>
                    <!-- L4 Transport -->
                    <div class="param-item" style="{% if layer_threats.layers.L4_TRANSPORT.critical > 0 %}background: #fee2e2; border-left: 4px solid var(--hp-red);{% elif layer_threats.layers.L4_TRANSPORT.high > 0 %}background: #fef3c7; border-left: 4px solid var(--hp-amber);{% else %}background: #d1fae5; border-left: 4px solid var(--hp-green);{% endif %}">
                        <div class="label">L4 Transport</div>
                        <div class="value" id="layer-l4">{{ layer_threats.layers.L4_TRANSPORT.total }}</div>
                        <div style="font-size: 10px; color: #6b7280; margin-top: 4px;">TCP, UDP, Ports</div>
                    </div>
                    <!-- L5 Session -->
                    <div class="param-item" style="{% if layer_threats.layers.L5_SESSION.critical > 0 %}background: #fee2e2; border-left: 4px solid var(--hp-red);{% elif layer_threats.layers.L5_SESSION.high > 0 %}background: #fef3c7; border-left: 4px solid var(--hp-amber);{% else %}background: #d1fae5; border-left: 4px solid var(--hp-green);{% endif %}">
                        <div class="label">L5 Session</div>
                        <div class="value" id="layer-l5">{{ layer_threats.layers.L5_SESSION.total }}</div>
                        <div style="font-size: 10px; color: #6b7280; margin-top: 4px;">SSL, Auth, Session</div>
                    </div>
                    <!-- L6 Presentation -->
                    <div class="param-item" style="{% if layer_threats.layers.L6_PRESENTATION.critical > 0 %}background: #fee2e2; border-left: 4px solid var(--hp-red);{% elif layer_threats.layers.L6_PRESENTATION.high > 0 %}background: #fef3c7; border-left: 4px solid var(--hp-amber);{% else %}background: #d1fae5; border-left: 4px solid var(--hp-green);{% endif %}">
                        <div class="label">L6 Presentation</div>
                        <div class="value" id="layer-l6">{{ layer_threats.layers.L6_PRESENTATION.total }}</div>
                        <div style="font-size: 10px; color: #6b7280; margin-top: 4px;">Encoding, Crypto</div>
                    </div>
                    <!-- L7 Application -->
                    <div class="param-item" style="{% if layer_threats.layers.L7_APPLICATION.critical > 0 %}background: #fee2e2; border-left: 4px solid var(--hp-red);{% elif layer_threats.layers.L7_APPLICATION.high > 0 %}background: #fef3c7; border-left: 4px solid var(--hp-amber);{% else %}background: #d1fae5; border-left: 4px solid var(--hp-green);{% endif %}">
                        <div class="label">L7 Application</div>
                        <div class="value" id="layer-l7">{{ layer_threats.layers.L7_APPLICATION.total }}</div>
                        <div style="font-size: 10px; color: #6b7280; margin-top: 4px;">HTTP, DNS, App</div>
                    </div>
                </div>

                <!-- Detection Coverage -->
                <h3>Detection Coverage</h3>
                <table class="data-table" style="font-size: 12px;">
                    <thead>
                        <tr>
                            <th>Layer</th>
                            <th>Threats</th>
                            <th>Critical</th>
                            <th>High</th>
                            <th>Med</th>
                            <th>Low</th>
                            <th>Blocked</th>
                            <th>Detection Types</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>L2</strong> Data Link</td>
                            <td>{{ layer_threats.layers.L2_DATA_LINK.total }}</td>
                            <td style="color: var(--hp-red);">{{ layer_threats.layers.L2_DATA_LINK.critical }}</td>
                            <td style="color: #dc2626;">{{ layer_threats.layers.L2_DATA_LINK.high }}</td>
                            <td style="color: var(--hp-amber);">{{ layer_threats.layers.L2_DATA_LINK.medium }}</td>
                            <td style="color: var(--hp-green);">{{ layer_threats.layers.L2_DATA_LINK.low }}</td>
                            <td>{{ layer_threats.layers.L2_DATA_LINK.blocked }}</td>
                            <td style="font-size: 11px;">{{ layer_threats.detection_coverage.L2_DATA_LINK | join(', ') }}</td>
                        </tr>
                        <tr>
                            <td><strong>L3</strong> Network</td>
                            <td>{{ layer_threats.layers.L3_NETWORK.total }}</td>
                            <td style="color: var(--hp-red);">{{ layer_threats.layers.L3_NETWORK.critical }}</td>
                            <td style="color: #dc2626;">{{ layer_threats.layers.L3_NETWORK.high }}</td>
                            <td style="color: var(--hp-amber);">{{ layer_threats.layers.L3_NETWORK.medium }}</td>
                            <td style="color: var(--hp-green);">{{ layer_threats.layers.L3_NETWORK.low }}</td>
                            <td>{{ layer_threats.layers.L3_NETWORK.blocked }}</td>
                            <td style="font-size: 11px;">{{ layer_threats.detection_coverage.L3_NETWORK | join(', ') }}</td>
                        </tr>
                        <tr>
                            <td><strong>L4</strong> Transport</td>
                            <td>{{ layer_threats.layers.L4_TRANSPORT.total }}</td>
                            <td style="color: var(--hp-red);">{{ layer_threats.layers.L4_TRANSPORT.critical }}</td>
                            <td style="color: #dc2626;">{{ layer_threats.layers.L4_TRANSPORT.high }}</td>
                            <td style="color: var(--hp-amber);">{{ layer_threats.layers.L4_TRANSPORT.medium }}</td>
                            <td style="color: var(--hp-green);">{{ layer_threats.layers.L4_TRANSPORT.low }}</td>
                            <td>{{ layer_threats.layers.L4_TRANSPORT.blocked }}</td>
                            <td style="font-size: 11px;">{{ layer_threats.detection_coverage.L4_TRANSPORT | join(', ') }}</td>
                        </tr>
                        <tr>
                            <td><strong>L5</strong> Session</td>
                            <td>{{ layer_threats.layers.L5_SESSION.total }}</td>
                            <td style="color: var(--hp-red);">{{ layer_threats.layers.L5_SESSION.critical }}</td>
                            <td style="color: #dc2626;">{{ layer_threats.layers.L5_SESSION.high }}</td>
                            <td style="color: var(--hp-amber);">{{ layer_threats.layers.L5_SESSION.medium }}</td>
                            <td style="color: var(--hp-green);">{{ layer_threats.layers.L5_SESSION.low }}</td>
                            <td>{{ layer_threats.layers.L5_SESSION.blocked }}</td>
                            <td style="font-size: 11px;">{{ layer_threats.detection_coverage.L5_SESSION | join(', ') }}</td>
                        </tr>
                        <tr>
                            <td><strong>L6</strong> Presentation</td>
                            <td>{{ layer_threats.layers.L6_PRESENTATION.total }}</td>
                            <td style="color: var(--hp-red);">{{ layer_threats.layers.L6_PRESENTATION.critical }}</td>
                            <td style="color: #dc2626;">{{ layer_threats.layers.L6_PRESENTATION.high }}</td>
                            <td style="color: var(--hp-amber);">{{ layer_threats.layers.L6_PRESENTATION.medium }}</td>
                            <td style="color: var(--hp-green);">{{ layer_threats.layers.L6_PRESENTATION.low }}</td>
                            <td>{{ layer_threats.layers.L6_PRESENTATION.blocked }}</td>
                            <td style="font-size: 11px;">{{ layer_threats.detection_coverage.L6_PRESENTATION | join(', ') }}</td>
                        </tr>
                        <tr>
                            <td><strong>L7</strong> Application</td>
                            <td>{{ layer_threats.layers.L7_APPLICATION.total }}</td>
                            <td style="color: var(--hp-red);">{{ layer_threats.layers.L7_APPLICATION.critical }}</td>
                            <td style="color: #dc2626;">{{ layer_threats.layers.L7_APPLICATION.high }}</td>
                            <td style="color: var(--hp-amber);">{{ layer_threats.layers.L7_APPLICATION.medium }}</td>
                            <td style="color: var(--hp-green);">{{ layer_threats.layers.L7_APPLICATION.low }}</td>
                            <td>{{ layer_threats.layers.L7_APPLICATION.blocked }}</td>
                            <td style="font-size: 11px;">{{ layer_threats.detection_coverage.L7_APPLICATION | join(', ') }}</td>
                        </tr>
                    </tbody>
                </table>
                <div style="margin-top: 15px;">
                    <button type="button" class="btn btn-secondary" onclick="refreshLayerThreats()">Refresh Layer Data</button>
                </div>
            </div>

            <!-- Threat Analysis - Top Priority -->
            <div class="card">
                <h2>Threat Analysis</h2>
                <div id="threat-visualization">
                    <div class="param-grid">
                        <div class="param-item" style="background: #fee2e2;">
                            <div class="label">High Severity</div>
                            <div class="value" id="threat-high" style="color: var(--hp-red);">0</div>
                        </div>
                        <div class="param-item" style="background: #fef3c7;">
                            <div class="label">Medium Severity</div>
                            <div class="value" id="threat-medium" style="color: var(--hp-amber);">0</div>
                        </div>
                        <div class="param-item" style="background: #d1fae5;">
                            <div class="label">Low Severity</div>
                            <div class="value" id="threat-low" style="color: var(--hp-green);">0</div>
                        </div>
                        <div class="param-item">
                            <div class="label">Total Threats</div>
                            <div class="value" id="threat-total">0</div>
                        </div>
                    </div>
                    <div style="margin-top: 15px;">
                        <button type="button" class="btn btn-secondary" onclick="refreshThreats()">Refresh Threats</button>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>QSecBit Security Status</h2>

                <!-- RAG Summary -->
                <div class="rag-grid">
                    <div class="rag-card {{ qsecbit.neuro.rag }}">
                        <div class="title">Neuro Protocol</div>
                        <div class="value">{{ qsecbit.neuro.status | upper }}</div>
                    </div>
                    <div class="rag-card {{ qsecbit.qsecbit.rag }}">
                        <div class="title">QSecBit Agent</div>
                        <div class="value">{{ qsecbit.qsecbit.status | upper }}</div>
                    </div>
                    <div class="rag-card {{ qsecbit.threats.rag }}">
                        <div class="title">Threat Level</div>
                        <div class="value">
                            {% if qsecbit.threats.rag == 'green' %}LOW
                            {% elif qsecbit.threats.rag == 'amber' %}MEDIUM
                            {% else %}HIGH{% endif %}
                        </div>
                    </div>
                    <div class="rag-card {{ qsecbit.suricata.rag }}">
                        <div class="title">IDS Status</div>
                        <div class="value">
                            {% if qsecbit.suricata.rag == 'green' %}CLEAR
                            {% elif qsecbit.suricata.rag == 'amber' %}ALERTS
                            {% else %}CRITICAL{% endif %}
                        </div>
                    </div>
                </div>

                <h3>Neuro Protocol Parameters</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Status</div>
                        <div class="value">{{ qsecbit.neuro.status }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">{{ qsecbit.neuro.mode }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Last Update</div>
                        <div class="value">{{ qsecbit.neuro.timestamp[:19] if qsecbit.neuro.timestamp else 'N/A' }}</div>
                    </div>
                </div>

                <h3>QSecBit Score &amp; Status</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">QSecBit Score</div>
                        <div class="value" style="font-size: 24px; font-weight: bold;">
                            {{ "%.3f" | format(qsecbit.qsecbit.score|default(0)) }}
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Status</div>
                        <div class="value">{{ qsecbit.qsecbit.status }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">{{ qsecbit.qsecbit.mode|default('guardian-edge') }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Version</div>
                        <div class="value">{{ qsecbit.qsecbit.version|default('5.0.0') }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Connections</div>
                        <div class="value">{{ qsecbit.qsecbit.connections }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Last Update</div>
                        <div class="value">{{ qsecbit.qsecbit.timestamp[:19] if qsecbit.qsecbit.timestamp else 'N/A' }}</div>
                    </div>
                </div>

                <h3>QSecBit Components (Weights)</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Drift (α=0.25)</div>
                        <div class="value">{{ "%.4f" | format(qsecbit.qsecbit.drift|default(0)) }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Attack Probability (β=0.25)</div>
                        <div class="value">{{ "%.4f" | format(qsecbit.qsecbit.attack_probability|default(0)) }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Classifier Decay (γ=0.20)</div>
                        <div class="value">{{ "%.4f" | format(qsecbit.qsecbit.classifier_decay|default(0)) }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Quantum Drift (δ=0.15)</div>
                        <div class="value">{{ "%.4f" | format(qsecbit.qsecbit.quantum_drift|default(0)) }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Energy Anomaly (ε=0.15)</div>
                        <div class="value">{{ "%.4f" | format(qsecbit.qsecbit.energy_anomaly|default(0)) }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Threats Detected</div>
                        <div class="value">{{ qsecbit.threats.count }}</div>
                    </div>
                </div>

                <h3>RAPL Energy Monitoring</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">RAPL Available</div>
                        <div class="value">
                            <span class="badge {% if qsecbit.qsecbit.rapl_available %}badge-success{% else %}badge-warning{% endif %}">
                                {% if qsecbit.qsecbit.rapl_available %}Yes{% else %}No{% endif %}
                            </span>
                        </div>
                    </div>
                </div>

                <h3>XDP/eBPF Inspection</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">XDP Status</div>
                        <div class="value">
                            <span class="badge {% if qsecbit.qsecbit.xdp_enabled %}badge-success{% else %}badge-warning{% endif %}">
                                {% if qsecbit.qsecbit.xdp_enabled %}Enabled{% else %}Disabled{% endif %}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">eBPF Programs</div>
                        <div class="value">{{ qsecbit.qsecbit.ebpf_programs | length }}</div>
                    </div>
                </div>
                {% if qsecbit.qsecbit.ebpf_programs %}
                <div style="margin-top: 10px;">
                    <pre style="background: #1f2937; color: #10b981; padding: 10px; border-radius: 8px; font-size: 11px; overflow-x: auto;">{% for prog in qsecbit.qsecbit.ebpf_programs %}{{ prog }}
{% endfor %}</pre>
                </div>
                {% endif %}
            </div>

            <div class="card">
                <h2>Interface Energy / Traffic Monitoring</h2>
                <div style="margin-bottom: 15px;">
                    <span class="rag-indicator rag-{{ qsecbit.energy.rag }}">
                        <span class="rag-dot"></span>
                        Total: {{ (qsecbit.energy.total_rx_bytes / 1048576) | round(2) }} MB RX / {{ (qsecbit.energy.total_tx_bytes / 1048576) | round(2) }} MB TX
                    </span>
                </div>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Interface</th>
                            <th>RX Bytes</th>
                            <th>TX Bytes</th>
                            <th>RX Packets</th>
                            <th>TX Packets</th>
                            <th>Errors</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for iface, stats in qsecbit.energy.interfaces.items() %}
                        <tr>
                            <td><strong>{{ iface }}</strong></td>
                            <td>{{ ((stats.rx_bytes or 0) / 1048576) | round(2) }} MB</td>
                            <td>{{ ((stats.tx_bytes or 0) / 1048576) | round(2) }} MB</td>
                            <td>{{ stats.rx_packets or 0 }}</td>
                            <td>{{ stats.tx_packets or 0 }}</td>
                            <td>{{ (stats.rx_errors or 0) + (stats.tx_errors or 0) }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Suricata IDS Alerts</h2>
                <div style="margin-bottom: 15px;">
                    <span class="rag-indicator rag-{{ qsecbit.suricata.rag }}">
                        <span class="rag-dot"></span>
                        {{ qsecbit.suricata.alert_count }} alerts detected
                    </span>
                </div>
                {% if qsecbit.suricata.alerts %}
                <div class="alert-list">
                    {% for alert in qsecbit.suricata.alerts %}
                    <div class="alert-item {% if alert.severity <= 2 %}sev-high{% elif alert.severity == 3 %}sev-medium{% else %}sev-low{% endif %}">
                        <div class="signature">{{ alert.signature }}</div>
                        <div class="meta">
                            {{ alert.timestamp }} | Severity: {{ alert.severity }} |
                            {{ alert.src_ip }} &rarr; {{ alert.dest_ip }}
                            {% if alert.category %}| {{ alert.category }}{% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <p style="color: #6b7280;">No alerts detected. Network is secure.</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>Threat Log</h2>
                <div style="margin-bottom: 15px;">
                    <span class="rag-indicator rag-{{ qsecbit.threats.rag }}">
                        <span class="rag-dot"></span>
                        {{ qsecbit.threats.count }} threats logged
                    </span>
                </div>
                {% if qsecbit.threats.recent %}
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Signature</th>
                            <th>Source</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for threat in qsecbit.threats.recent %}
                        <tr>
                            <td>{{ threat.timestamp[:19] if threat.timestamp else 'N/A' }}</td>
                            <td>{{ threat.signature or 'Unknown' }}</td>
                            <td>{{ threat.src_ip or 'N/A' }}</td>
                            <td>{{ threat.severity or 0 }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p style="color: #6b7280;">No threats logged.</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>OVS / VXLAN Configuration</h2>
                <div style="margin-bottom: 15px;">
                    <span class="rag-indicator rag-{{ qsecbit.ovs.rag }}">
                        <span class="rag-dot"></span>
                        {% if qsecbit.ovs.config %}Configured{% else %}Not configured{% endif %}
                    </span>
                </div>
                {% if qsecbit.ovs.config %}
                <div class="param-grid">
                    {% for key, value in qsecbit.ovs.config.items() %}
                    <div class="param-item">
                        <div class="label">{{ key }}</div>
                        <div class="value">{{ value }}</div>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}

                {% if qsecbit.ovs.bridges %}
                <h3>OVS Bridges</h3>
                <pre style="background: #1f2937; color: #10b981; padding: 15px; border-radius: 8px; font-size: 12px; overflow-x: auto;">{{ qsecbit.ovs.bridges }}</pre>
                {% endif %}
            </div>

            <!-- IP Blocking -->
            <div class="card">
                <h2>IP Blocking (XDP)</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Block malicious IPs at the kernel level using XDP/eBPF for maximum performance.
                </p>
                <div class="form-group">
                    <label>IP Address to Block</label>
                    <div class="test-input-row">
                        <input type="text" id="block-ip-input" placeholder="e.g., 192.168.1.100">
                        <button type="button" class="btn btn-danger" onclick="blockIP()">Block IP</button>
                    </div>
                </div>
                <div id="block-ip-result" style="margin-top: 10px;"></div>

                <!-- XDP Stats -->
                <div id="xdp-stats" style="margin-top: 20px;">
                    <h3>XDP Protection Stats</h3>
                    <div class="param-grid" id="xdp-stats-grid">
                        <div class="param-item">
                            <div class="label">Packets Passed</div>
                            <div class="value" id="xdp-passed">-</div>
                        </div>
                        <div class="param-item">
                            <div class="label">Packets Dropped</div>
                            <div class="value" id="xdp-dropped">-</div>
                        </div>
                        <div class="param-item">
                            <div class="label">Rate Limited</div>
                            <div class="value" id="xdp-rate-limited">-</div>
                        </div>
                        <div class="param-item">
                            <div class="label">Blocklisted</div>
                            <div class="value" id="xdp-blocklisted">-</div>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="refreshXdpStats()" style="margin-top: 10px;">Refresh Stats</button>
                </div>
            </div>

            <!-- Security Testing -->
            <div class="card">
                <h2>Security Testing</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Run automated security tests to verify IDS/IPS, WAF, and XDP protection are working correctly.
                </p>
                <div class="form-group">
                    <label>Target IP (default: Guardian itself)</label>
                    <div class="test-input-row">
                        <input type="text" id="test-target" value="192.168.4.1">
                        <button type="button" class="btn btn-primary" onclick="runSecurityTest()">Run Test</button>
                    </div>
                </div>
                <div id="test-status" style="margin-top: 15px; display: none;">
                    <div class="alert-item" style="background: var(--hp-light); padding: 15px; border-radius: 8px;">
                        <span id="test-status-text">Test running...</span>
                    </div>
                </div>
                <div id="test-results" style="margin-top: 15px;"></div>
            </div>
        </div>

        <!-- WiFi Tab - All WiFi Settings -->
        <div id="wifi" class="tab-content">
            <div class="card">
                <h2>Hotspot Settings</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Configure the WiFi hotspot that clients connect to.
                </p>
                <form method="post" action="/hotspot">
                    <div class="form-group">
                        <label>Hotspot Name (SSID)</label>
                        <input type="text" name="ssid" value="{{ config.hotspot_ssid }}" required>
                    </div>
                    <div class="form-group">
                        <label>Password (min 8 characters)</label>
                        <input type="password" name="password" value="{{ config.hotspot_password }}" minlength="8" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Hotspot Settings</button>
                </form>
            </div>

            <div class="card">
                <h2>Upstream WiFi Connection</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">
                    Connect Guardian to an existing WiFi network for internet access.
                </p>
                <form method="post" action="/connect">
                    <div class="form-group">
                        <label>Network Name (SSID)</label>
                        <input type="text" name="ssid" id="upstream-ssid" value="{{ config.upstream_ssid }}" placeholder="Select from list below or type manually">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" value="{{ config.upstream_password }}">
                    </div>
                    <div class="btn-group">
                        <button type="submit" class="btn btn-primary">Connect</button>
                        <button type="button" id="scan-btn" class="btn btn-secondary" onclick="scanNetworks()">Scan Networks</button>
                    </div>
                </form>

                <!-- Scan Results Container -->
                <div id="scan-results" style="margin-top: 20px;">
                    <div id="scan-status" style="display: none; padding: 15px; background: var(--hp-light); border-radius: 8px; margin-bottom: 15px;">
                        <span id="scan-status-text">Scanning for networks...</span>
                    </div>
                    <div id="networks-container"></div>
                </div>
            </div>

            <div class="card">
                <h2>Interface Status</h2>

                <!-- Summary of detected interfaces -->
                <div style="margin-bottom: 20px; padding: 12px; background: var(--hp-light); border-radius: 8px;">
                    <strong>Detected WiFi:</strong>
                    {% if status.wireless_interfaces %}
                        {{ status.wireless_interfaces | join(', ') }}
                    {% else %}
                        wlan0, wlan1 (default)
                    {% endif %}
                    {% if status.eth0.carrier %}
                    <span style="margin-left: 15px;"><strong>Ethernet:</strong> eth0 (connected)</span>
                    {% endif %}
                </div>

                <h3>LAN Interface - Hotspot ({{ status.lan_interface.interface }})</h3>
                <p style="color: #6b7280; font-size: 12px; margin-bottom: 10px;">Broadcasts Guardian SSID for client connections</p>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">
                            <span class="badge {% if status.lan_interface.type == 'AP' %}badge-success{% else %}badge-warning{% endif %}">
                                {{ status.lan_interface.type | upper }}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Hardware</div>
                        <div class="value">
                            {% if status.lan_interface.is_builtin %}
                                Built-in WiFi
                            {% else %}
                                USB Dongle
                            {% endif %}
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Driver</div>
                        <div class="value">{{ status.lan_interface.driver or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">SSID</div>
                        <div class="value">{{ status.lan_interface.ssid or config.hotspot_ssid }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Channel</div>
                        <div class="value">{{ status.lan_interface.channel or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">TX Power</div>
                        <div class="value">{{ status.lan_interface.tx_power or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">MAC Address</div>
                        <div class="value">{{ status.lan_interface.mac or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Connected Clients</div>
                        <div class="value">{{ status.clients }}</div>
                    </div>
                </div>

                <h3>WAN Interface - Internet ({{ status.wan_interface.interface }})</h3>
                <p style="color: #6b7280; font-size: 12px; margin-bottom: 10px;">Connects to upstream network for internet access</p>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">
                            <span class="badge {% if status.wan_interface.type in ['managed', 'wired'] %}badge-success{% else %}badge-warning{% endif %}">
                                {{ status.wan_interface.type | upper }}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Hardware</div>
                        <div class="value">
                            {% if status.wan_interface.type == 'wired' %}
                                Ethernet
                            {% elif status.wan_interface.is_builtin %}
                                Built-in WiFi
                            {% else %}
                                USB Dongle
                            {% endif %}
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Driver</div>
                        <div class="value">{{ status.wan_interface.driver or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Status</div>
                        <div class="value">
                            <span class="badge {% if status.wan_connected %}badge-success{% else %}badge-danger{% endif %}">
                                {% if status.wan_connected %}Connected{% else %}Disconnected{% endif %}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Network</div>
                        <div class="value">{{ status.wan_interface.ssid or 'Not connected' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Signal</div>
                        <div class="value">{{ status.wan_interface.signal or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Channel</div>
                        <div class="value">{{ status.wan_interface.channel or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">MAC Address</div>
                        <div class="value">{{ status.wan_interface.mac or 'N/A' }}</div>
                    </div>
                </div>

                {% if status.eth0.carrier %}
                <h3>Ethernet (eth0)</h3>
                <p style="color: #6b7280; font-size: 12px; margin-bottom: 10px;">Can be bridged to WAN for wired internet</p>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Status</div>
                        <div class="value">
                            <span class="badge badge-success">Connected</span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">IP Address</div>
                        <div class="value">{{ status.eth0.ip or 'DHCP' }}</div>
                    </div>
                </div>
                {% endif %}

                <!-- Show all interfaces if more than 2 -->
                {% if status.all_interfaces and status.all_interfaces|length > 2 %}
                <h3>All Wireless Interfaces</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Interface</th>
                            <th>Mode</th>
                            <th>Role</th>
                            <th>Hardware</th>
                            <th>SSID</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for iface, info in status.all_interfaces.items() %}
                        <tr>
                            <td><strong>{{ iface }}</strong></td>
                            <td>{{ info.type | upper }}</td>
                            <td>{{ info.role | capitalize }}</td>
                            <td>{% if info.is_builtin %}Built-in{% else %}USB{% endif %}</td>
                            <td>{{ info.ssid or 'N/A' }}</td>
                            <td>
                                <span class="badge {% if info.connected %}badge-success{% else %}badge-warning{% endif %}">
                                    {% if info.connected %}Active{% else %}Inactive{% endif %}
                                </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
            </div>
        </div>

        <!-- Clients Tab -->
        <div id="clients" class="tab-content">
            <div class="card">
                <h2>Connected Clients</h2>
                <p style="color: #6b7280; margin-bottom: 20px;">Manage devices connected to the Guardian hotspot</p>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="value" id="clients-total">{{ clients|length if clients else 0 }}</div>
                        <div class="label">Connected Clients</div>
                    </div>
                    <div class="status-item">
                        <div class="value" style="color: var(--hp-green);" id="clients-active">{{ clients|length if clients else 0 }}</div>
                        <div class="label">Active</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Client List</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">Click "Disconnect" to remove a client from the network</p>
                <div style="overflow-x: auto;">
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th>MAC Address</th>
                                <th>IP Address</th>
                                <th>Hostname</th>
                                <th>Connected</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="clients-table-body">
                            {% if clients %}
                            {% for client in clients %}
                            <tr id="client-row-{{ client.mac|replace(':', '-') }}">
                                <td><code>{{ client.mac }}</code></td>
                                <td>{{ client.ip }}</td>
                                <td>{{ client.hostname or client.name or 'Unknown' }}</td>
                                <td>{{ client.connected_time or 'N/A' }}</td>
                                <td>
                                    <button class="btn btn-sm btn-danger" onclick="disconnectClient('{{ client.mac }}', '{{ client.hostname or client.name or client.mac }}')">Disconnect</button>
                                </td>
                            </tr>
                            {% endfor %}
                            {% else %}
                            <tr id="no-clients-row">
                                <td colspan="5" style="text-align: center; color: #6b7280;">No clients connected</td>
                            </tr>
                            {% endif %}
                        </tbody>
                    </table>
                </div>
                <div style="margin-top: 15px;">
                    <button class="btn btn-secondary" onclick="refreshClients()">Refresh Client List</button>
                </div>
            </div>
        </div>

        <!-- AdGuard Tab -->
        <div id="adguard" class="tab-content">
            <div class="card">
                <h2>AdGuard Home DNS</h2>
                <p style="color: #6b7280; margin-bottom: 20px;">Network-wide ad blocking and DNS filtering</p>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="value" style="color: {% if containers.adguard.running %}var(--hp-green){% else %}var(--hp-red){% endif %};">
                            {% if containers.adguard.running %}Running{% else %}Stopped{% endif %}
                        </div>
                        <div class="label">Service Status</div>
                    </div>
                    <div class="status-item">
                        <div class="value" id="adguard-queries">-</div>
                        <div class="label">DNS Queries (24h)</div>
                    </div>
                    <div class="status-item">
                        <div class="value" id="adguard-blocked">-</div>
                        <div class="label">Blocked (24h)</div>
                    </div>
                    <div class="status-item">
                        <div class="value" id="adguard-percent">-</div>
                        <div class="label">Block Rate</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>AdGuard Dashboard</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">Access the full AdGuard Home interface for detailed configuration</p>
                <div style="background: var(--hp-light); border-radius: 8px; padding: 12px; margin-bottom: 15px; font-size: 13px;">
                    <strong>Default Login:</strong> admin / hookprobe123
                </div>
                <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                    <a href="http://192.168.4.1:3000" target="_blank" class="btn btn-primary">
                        Open AdGuard Dashboard
                    </a>
                    <button class="btn btn-secondary" onclick="refreshAdGuardStats()">
                        Refresh Stats
                    </button>
                </div>
                <div style="background: var(--hp-light); border-radius: 8px; padding: 15px;">
                    <h3 style="margin-bottom: 10px; font-size: 14px;">Quick Access</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px;">
                        <a href="http://192.168.4.1:3000/#filters" target="_blank" style="color: var(--hp-primary); text-decoration: none; font-size: 13px;">
                            → Filters & Blocklists
                        </a>
                        <a href="http://192.168.4.1:3000/#dns" target="_blank" style="color: var(--hp-primary); text-decoration: none; font-size: 13px;">
                            → DNS Settings
                        </a>
                        <a href="http://192.168.4.1:3000/#clients" target="_blank" style="color: var(--hp-primary); text-decoration: none; font-size: 13px;">
                            → Client Settings
                        </a>
                        <a href="http://192.168.4.1:3000/#logs" target="_blank" style="color: var(--hp-primary); text-decoration: none; font-size: 13px;">
                            → Query Log
                        </a>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>DNS Configuration</h2>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">AdGuard Port</div>
                        <div class="value">3000 (Web), 53 (DNS)</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Container</div>
                        <div class="value">guardian-adguard</div>
                    </div>
                    <div class="param-item">
                        <div class="label">DNS Server</div>
                        <div class="value">192.168.4.1:53</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Upstream DNS</div>
                        <div class="value">1.1.1.1, 8.8.8.8</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Service Controls</h2>
                <div class="btn-group" style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <form method="POST" action="/action" style="display: inline;">
                        <input type="hidden" name="action" value="restart_adguard">
                        <button type="submit" class="btn btn-warning">Restart AdGuard</button>
                    </form>
                    <form method="POST" action="/action" style="display: inline;">
                        <input type="hidden" name="action" value="flush_dns">
                        <button type="submit" class="btn btn-secondary">Flush DNS Cache</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- VPN Tab (HTP File Transfer) -->
        <div id="vpn" class="tab-content">
            <div class="card">
                <h2>HTP File Transfer Status</h2>
                <p style="color: #6b7280; margin-bottom: 20px;">Secure file access via MSSP using HTP (weight-bound encryption + PoSF authentication)</p>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="value" style="color: {% if vpn_stats.connected %}var(--hp-green){% else %}var(--hp-red){% endif %};" id="vpn-state">
                            {% if vpn_stats.connected %}Connected{% else %}Disconnected{% endif %}
                        </div>
                        <div class="label">HTP Session</div>
                    </div>
                    <div class="status-item">
                        <div class="value" id="vpn-sessions">{{ vpn_stats.active_transfers }}</div>
                        <div class="label">Active Transfers</div>
                    </div>
                    <div class="status-item">
                        <div class="value" id="vpn-rx">{{ (vpn_stats.rx_bytes / 1024 / 1024)|round(2) }} MB</div>
                        <div class="label">Data Received</div>
                    </div>
                    <div class="status-item">
                        <div class="value" id="vpn-tx">{{ (vpn_stats.tx_bytes / 1024 / 1024)|round(2) }} MB</div>
                        <div class="label">Data Sent</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Connection Details</h2>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">MSSP Server</div>
                        <div class="value">{{ vpn_stats.mssp_host }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Protocol</div>
                        <div class="value">HTP (Neuro Protocol)</div>
                    </div>
                    <div class="param-item">
                        <div class="label">HTP Session</div>
                        <div class="value">
                            <span class="badge {% if vpn_stats.htp_session %}badge-success{% else %}badge-warning{% endif %}">
                                {% if vpn_stats.htp_session %}Active{% else %}Inactive{% endif %}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Uptime</div>
                        <div class="value">{{ vpn_stats.uptime or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Last Activity</div>
                        <div class="value">{{ vpn_stats.last_activity or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Packets (RX/TX)</div>
                        <div class="value">{{ vpn_stats.rx_packets }} / {{ vpn_stats.tx_packets }}</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Allowed Paths</h2>
                <p style="color: #6b7280; margin-bottom: 15px;">Files accessible through HTP file transfer</p>
                <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                    {% for path in vpn_stats.allowed_paths %}
                    <div style="background: #1f2937; padding: 8px 15px; border-radius: 6px;">
                        <code style="color: var(--hp-primary);">{{ path }}</code>
                    </div>
                    {% endfor %}
                </div>
            </div>

            {% if vpn_stats.file_transfers %}
            <div class="card">
                <h2>Recent File Transfers</h2>
                <div style="overflow-x: auto;">
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Operation</th>
                                <th>Path</th>
                                <th>Size</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for transfer in vpn_stats.file_transfers %}
                            <tr>
                                <td>{{ transfer.time }}</td>
                                <td>{{ transfer.operation }}</td>
                                <td><code>{{ transfer.path }}</code></td>
                                <td>{{ transfer.size }}</td>
                                <td>
                                    <span class="badge {% if transfer.status == 'success' %}badge-success{% else %}badge-danger{% endif %}">
                                        {{ transfer.status }}
                                    </span>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endif %}

            <div class="card">
                <h2>VPN Actions</h2>
                <form method="post" action="/action">
                    <div class="btn-group">
                        <button type="submit" name="action" value="vpn_reconnect" class="btn btn-primary">Reconnect VPN</button>
                        <button type="submit" name="action" value="vpn_disconnect" class="btn btn-secondary">Disconnect</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- System Tab -->
        <div id="system" class="tab-content">
            <div class="card">
                <h2>System Information</h2>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">{{ config.mode | upper }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">IP Addresses</div>
                        <div class="value">{{ status.ip_addresses | join(', ') }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Uptime</div>
                        <div class="value">{{ status.uptime }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Memory Usage</div>
                        <div class="value">{{ status.memory_usage }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Disk Usage</div>
                        <div class="value">{{ status.disk_usage }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">CPU Temperature</div>
                        <div class="value">{{ status.cpu_temp }}</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Container Management</h2>
                <div class="container-grid" style="margin-bottom: 20px;">
                    {% for key, container in containers.items() %}
                    <div class="container-item">
                        <span class="name">{{ container.label }}</span>
                        <span class="badge {% if container.running %}badge-success{% else %}badge-danger{% endif %}">
                            {% if container.running %}Running{% else %}Stopped{% endif %}
                        </span>
                    </div>
                    {% endfor %}
                </div>
                <form method="post" action="/action">
                    <button type="submit" name="action" value="restart_containers" class="btn btn-secondary">Restart All Containers</button>
                </form>
            </div>

            <div class="card">
                <h2>System Actions</h2>
                <form method="post" action="/action">
                    <div class="btn-group">
                        <button type="submit" name="action" value="restart_hostapd" class="btn btn-primary">Restart Hotspot</button>
                        <button type="submit" name="action" value="restart_network" class="btn btn-secondary">Restart Network</button>
                        <button type="submit" name="action" value="restart_services" class="btn btn-secondary">Restart All Services</button>
                        <button type="submit" name="action" value="reboot" class="btn btn-danger" onclick="return confirm('Reboot Guardian?')">Reboot System</button>
                    </div>
                </form>
            </div>

        </div>
    </div>

    <div class="footer">
        <p>HookProbe Guardian v5.0.0 | Protection on the Move | <a href="https://hookprobe.com" target="_blank">hookprobe.com</a></p>
    </div>

    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
                window.location.hash = tab.dataset.tab;
            });
        });

        // Check URL hash for tab
        if (window.location.hash) {
            const tabId = window.location.hash.substring(1);
            const tab = document.querySelector(`.tab[data-tab="${tabId}"]`);
            if (tab) tab.click();
        }

        // WiFi Network Scanning (on-demand via AJAX)
        let isScanning = false;

        function scanNetworks() {
            if (isScanning) return;
            isScanning = true;

            const btn = document.getElementById('scan-btn');
            const statusDiv = document.getElementById('scan-status');
            const statusText = document.getElementById('scan-status-text');
            const container = document.getElementById('networks-container');

            // Show scanning status
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            statusDiv.style.display = 'block';
            statusText.textContent = 'Scanning for WiFi networks... This may take up to 30 seconds.';
            container.innerHTML = '';

            fetch('/api/scan')
                .then(response => response.json())
                .then(networks => {
                    isScanning = false;
                    btn.disabled = false;
                    btn.textContent = 'Scan Networks';

                    if (networks && networks.length > 0) {
                        statusText.textContent = `Found ${networks.length} network(s). Click on a network to select it.`;
                        let html = `
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>SSID</th>
                                        <th>Signal</th>
                                        <th>Channel</th>
                                        <th>Security</th>
                                    </tr>
                                </thead>
                                <tbody>
                        `;
                        networks.forEach(net => {
                            html += `
                                <tr style="cursor: pointer;" onclick="selectNetwork('${net.ssid.replace(/'/g, "\\'")}')">
                                    <td><strong>${net.ssid}</strong></td>
                                    <td>${net.signal} dBm</td>
                                    <td>${net.channel || 'N/A'}</td>
                                    <td>${net.security || 'Open'}</td>
                                </tr>
                            `;
                        });
                        html += '</tbody></table>';
                        container.innerHTML = html;
                    } else {
                        statusText.textContent = 'No networks found. Try scanning again.';
                        container.innerHTML = '<p style="color: #6b7280; margin-top: 10px;">No WiFi networks were detected. Make sure WiFi is enabled and try again.</p>';
                    }
                })
                .catch(error => {
                    isScanning = false;
                    btn.disabled = false;
                    btn.textContent = 'Scan Networks';
                    statusText.textContent = 'Scan failed. Please try again.';
                    container.innerHTML = '<p style="color: #ef4444; margin-top: 10px;">Error scanning for networks: ' + error.message + '</p>';
                });
        }

        function selectNetwork(ssid) {
            document.getElementById('upstream-ssid').value = ssid;
            // Highlight the selection
            document.getElementById('upstream-ssid').focus();
        }

        // IP Blocking
        function blockIP() {
            const ip = document.getElementById('block-ip-input').value.trim();
            const resultDiv = document.getElementById('block-ip-result');

            if (!ip) {
                resultDiv.innerHTML = '<span style="color: #ef4444;">Please enter an IP address</span>';
                return;
            }

            // Simple IP validation
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipRegex.test(ip)) {
                resultDiv.innerHTML = '<span style="color: #ef4444;">Invalid IP address format</span>';
                return;
            }

            resultDiv.innerHTML = '<span style="color: #6b7280;">Blocking IP...</span>';

            fetch('/api/block_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    resultDiv.innerHTML = '<span style="color: #22c55e;">IP ' + ip + ' blocked successfully</span>';
                    document.getElementById('block-ip-input').value = '';
                    refreshXdpStats();
                } else {
                    resultDiv.innerHTML = '<span style="color: #ef4444;">Error: ' + (data.error || 'Unknown error') + '</span>';
                }
            })
            .catch(error => {
                resultDiv.innerHTML = '<span style="color: #ef4444;">Error: ' + error.message + '</span>';
            });
        }

        // Refresh XDP Stats
        function refreshXdpStats() {
            fetch('/api/xdp_stats')
                .then(response => response.json())
                .then(data => {
                    if (data.stats) {
                        document.getElementById('xdp-passed').textContent = data.stats.passed || '0';
                        document.getElementById('xdp-dropped').textContent = data.stats.dropped || '0';
                        document.getElementById('xdp-rate-limited').textContent = data.stats.rate_limited || '0';
                        document.getElementById('xdp-blocklisted').textContent = data.stats.blocklisted || '0';
                    }
                })
                .catch(error => {
                    console.error('Error fetching XDP stats:', error);
                });
        }

        // Client Management
        function disconnectClient(mac, name) {
            if (!confirm(`Disconnect client "${name}" (${mac}) from the network?`)) return;

            fetch(`/api/clients/${encodeURIComponent(mac)}/disconnect`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                    // Remove the row from the table
                    const row = document.getElementById('client-row-' + mac.replace(/:/g, '-'));
                    if (row) row.remove();
                    // Update client count
                    refreshClients();
                } else {
                    alert('Error: ' + (data.error || 'Failed to disconnect client'));
                }
            })
            .catch(error => {
                alert('Error: ' + error.message);
            });
        }

        // Refresh Clients List
        function refreshClients() {
            fetch('/api/clients')
                .then(response => response.json())
                .then(data => {
                    if (data) {
                        document.getElementById('clients-total').textContent = data.length || 0;
                        document.getElementById('clients-active').textContent = data.length || 0;

                        // Update table
                        const tbody = document.getElementById('clients-table-body');
                        if (data.length === 0) {
                            tbody.innerHTML = '<tr id="no-clients-row"><td colspan="5" style="text-align: center; color: #6b7280;">No clients connected</td></tr>';
                        } else {
                            tbody.innerHTML = data.map(client => `
                                <tr id="client-row-${client.mac.replace(/:/g, '-')}">
                                    <td><code>${client.mac}</code></td>
                                    <td>${client.ip}</td>
                                    <td>${client.hostname || client.name || 'Unknown'}</td>
                                    <td>${client.connected_time || 'N/A'}</td>
                                    <td>
                                        <button class="btn btn-sm btn-danger" onclick="disconnectClient('${client.mac}', '${client.hostname || client.name || client.mac}')">Disconnect</button>
                                    </td>
                                </tr>
                            `).join('');
                        }
                    }
                })
                .catch(error => console.error('Error fetching clients:', error));
        }

        // Refresh AdGuard Stats
        function refreshAdGuardStats() {
            fetch('/api/adguard')
                .then(response => response.json())
                .then(data => {
                    if (data) {
                        document.getElementById('adguard-queries').textContent = data.num_dns_queries || '0';
                        document.getElementById('adguard-blocked').textContent = data.num_blocked_filtering || '0';
                        document.getElementById('adguard-percent').textContent = (data.blocked_percent || 0).toFixed(1) + '%';
                    }
                })
                .catch(error => {
                    console.error('Error fetching AdGuard stats:', error);
                    document.getElementById('adguard-queries').textContent = 'N/A';
                    document.getElementById('adguard-blocked').textContent = 'N/A';
                    document.getElementById('adguard-percent').textContent = 'N/A';
                });
        }

        // Load AdGuard stats on tab switch
        document.querySelectorAll('.tab[data-tab="adguard"]').forEach(tab => {
            tab.addEventListener('click', refreshAdGuardStats);
        });

        // Refresh VPN Stats
        function refreshVpnStats() {
            fetch('/api/vpn')
                .then(response => response.json())
                .then(data => {
                    if (data) {
                        const stateEl = document.getElementById('vpn-state');
                        stateEl.textContent = data.connected ? 'Connected' : 'Disconnected';
                        stateEl.style.color = data.connected ? 'var(--hp-green)' : 'var(--hp-red)';
                        document.getElementById('vpn-sessions').textContent = data.active_sessions || 0;
                        document.getElementById('vpn-rx').textContent = ((data.rx_bytes || 0) / 1024 / 1024).toFixed(2) + ' MB';
                        document.getElementById('vpn-tx').textContent = ((data.tx_bytes || 0) / 1024 / 1024).toFixed(2) + ' MB';
                    }
                })
                .catch(error => console.error('Error fetching VPN stats:', error));
        }

        // Auto-refresh clients and VPN stats every 10 seconds
        setInterval(refreshClients, 10000);
        setInterval(refreshVpnStats, 10000);

        // Run Security Test
        let testPollInterval = null;

        function runSecurityTest() {
            const target = document.getElementById('test-target').value.trim();
            const statusDiv = document.getElementById('test-status');
            const statusText = document.getElementById('test-status-text');
            const resultsDiv = document.getElementById('test-results');

            statusDiv.style.display = 'block';
            statusText.textContent = 'Starting security test...';
            resultsDiv.innerHTML = '';

            fetch('/api/security_test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    statusText.textContent = 'Test running... Polling for results.';
                    // Poll for results
                    testPollInterval = setInterval(pollTestResults, 3000);
                } else {
                    statusText.textContent = 'Failed to start test: ' + (data.error || 'Unknown error');
                }
            })
            .catch(error => {
                statusText.textContent = 'Error starting test: ' + error.message;
            });
        }

        function pollTestResults() {
            fetch('/api/security_test_result')
                .then(response => response.json())
                .then(data => {
                    const statusText = document.getElementById('test-status-text');
                    const resultsDiv = document.getElementById('test-results');

                    if (data.status === 'completed') {
                        clearInterval(testPollInterval);
                        statusText.textContent = 'Test completed!';

                        let html = '<div style="background: var(--hp-light); padding: 15px; border-radius: 8px; margin-top: 10px;">';
                        html += '<h4 style="margin-bottom: 10px;">Test Results</h4>';

                        if (data.results) {
                            for (const [test, result] of Object.entries(data.results)) {
                                const passed = result.passed;
                                const icon = passed ? '&#10003;' : '&#10007;';
                                const color = passed ? '#22c55e' : '#ef4444';
                                html += '<div style="margin-bottom: 8px;"><span style="color: ' + color + ';">' + icon + '</span> ' + test + ': ' + result.message + '</div>';
                            }
                        }
                        html += '</div>';
                        resultsDiv.innerHTML = html;

                        // Refresh threat data after test
                        refreshThreats();
                    } else if (data.status === 'running') {
                        statusText.textContent = 'Test running... ' + (data.progress || '');
                    } else if (data.status === 'error') {
                        clearInterval(testPollInterval);
                        statusText.textContent = 'Test failed: ' + (data.error || 'Unknown error');
                    }
                })
                .catch(error => {
                    clearInterval(testPollInterval);
                    document.getElementById('test-status-text').textContent = 'Error polling results: ' + error.message;
                });
        }

        // Refresh Threats
        function refreshThreats() {
            fetch('/api/threats')
                .then(response => response.json())
                .then(data => {
                    if (data.stats) {
                        document.getElementById('threat-high').textContent = data.stats.high || '0';
                        document.getElementById('threat-medium').textContent = data.stats.medium || '0';
                        document.getElementById('threat-low').textContent = data.stats.low || '0';
                        document.getElementById('threat-total').textContent = data.stats.total || '0';
                    }
                })
                .catch(error => {
                    console.error('Error fetching threats:', error);
                });
        }

        // Refresh Layer Threats (L2-L7)
        function refreshLayerThreats() {
            fetch('/api/layer_threats')
                .then(response => response.json())
                .then(data => {
                    if (data.layers) {
                        // Update layer counts
                        document.getElementById('layer-l2').textContent = data.layers.L2_DATA_LINK?.total || '0';
                        document.getElementById('layer-l3').textContent = data.layers.L3_NETWORK?.total || '0';
                        document.getElementById('layer-l4').textContent = data.layers.L4_TRANSPORT?.total || '0';
                        document.getElementById('layer-l5').textContent = data.layers.L5_SESSION?.total || '0';
                        document.getElementById('layer-l6').textContent = data.layers.L6_PRESENTATION?.total || '0';
                        document.getElementById('layer-l7').textContent = data.layers.L7_APPLICATION?.total || '0';
                    }
                })
                .catch(error => {
                    console.error('Error fetching layer threats:', error);
                });
        }

        // Refresh Mobile Protection Status
        function refreshMobileProtection() {
            fetch('/api/mobile_protection')
                .then(response => response.json())
                .then(data => {
                    // Update mobile protection display via page reload for now
                    // (full update would require more DOM manipulation)
                    console.log('Mobile protection data:', data);
                })
                .catch(error => {
                    console.error('Error fetching mobile protection:', error);
                });
        }

        // Refresh Threat Chart
        function refreshThreatChart() {
            fetch('/api/threats')
                .then(response => response.json())
                .then(data => {
                    const stats = data.stats || {};
                    const high = parseInt(stats.high) || 0;
                    const medium = parseInt(stats.medium) || 0;
                    const low = parseInt(stats.low) || 0;
                    const total = high + medium + low;

                    // Update values
                    document.getElementById('chart-value-high').textContent = high;
                    document.getElementById('chart-value-medium').textContent = medium;
                    document.getElementById('chart-value-low').textContent = low;
                    document.getElementById('chart-total').innerHTML = 'Total Threats: <strong>' + total + '</strong>';

                    // Update bar heights (max 100px, min 10px)
                    const maxVal = Math.max(high, medium, low, 1);
                    const scale = 100 / maxVal;

                    document.getElementById('chart-bar-high').style.height = Math.max(10, high * scale) + 'px';
                    document.getElementById('chart-bar-medium').style.height = Math.max(10, medium * scale) + 'px';
                    document.getElementById('chart-bar-low').style.height = Math.max(10, low * scale) + 'px';
                })
                .catch(error => {
                    console.error('Error refreshing threat chart:', error);
                });
        }

        // Initial load of security stats
        document.addEventListener('DOMContentLoaded', function() {
            refreshXdpStats();
            refreshThreats();
            refreshThreatChart();
            refreshLayerThreats();
        });

        // Background refresh - updates data without reloading page
        // This preserves user input (SSID, password fields, etc.)
        function backgroundRefresh() {
            // Don't refresh if user is scanning or running tests
            if (isScanning || testPollInterval) {
                return;
            }

            // Refresh threat data
            refreshThreatChart();
            refreshThreats();
            refreshXdpStats();
            refreshLayerThreats();

            // Refresh container status
            fetch('/api/containers')
                .then(response => response.json())
                .then(containers => {
                    // Update container badges in the UI
                    for (const [key, container] of Object.entries(containers)) {
                        const items = document.querySelectorAll('.container-item');
                        items.forEach(item => {
                            if (item.textContent.includes(container.label)) {
                                const badge = item.querySelector('.badge');
                                if (badge) {
                                    badge.className = 'badge ' + (container.running ? 'badge-success' : 'badge-danger');
                                    badge.textContent = container.running ? 'Running' : 'Stopped';
                                }
                            }
                        });
                    }
                })
                .catch(error => console.error('Error refreshing containers:', error));

            // Refresh network status
            fetch('/api/status')
                .then(response => response.json())
                .then(status => {
                    // Update client count if element exists
                    const clientElements = document.querySelectorAll('.status-item .value');
                    clientElements.forEach(el => {
                        if (el.nextElementSibling && el.nextElementSibling.textContent.includes('Connected Clients')) {
                            el.textContent = status.clients || '0';
                        }
                    });
                })
                .catch(error => console.error('Error refreshing status:', error));
        }

        // Auto-refresh every 30 seconds using background AJAX (preserves form input)
        setInterval(backgroundRefresh, 30000);

        // Also refresh when tab becomes visible again
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                backgroundRefresh();
            }
        });
    </script>
</body>
</html>
'''


@app.route('/logo.png')
def serve_logo():
    """Serve the HookProbe emblem logo."""
    if LOGO_FILE.exists():
        return send_file(LOGO_FILE, mimetype='image/png')
    # Return a 1x1 transparent pixel if logo not found
    return '', 204


@app.route('/')
def index():
    config = get_current_config()
    status = get_status()
    clients = get_connected_clients()
    vpn_stats = get_vpn_stats()
    containers = get_container_status()
    qsecbit = get_qsecbit_data()
    layer_threats = get_layer_threat_data()
    mobile_protection = get_mobile_protection_data()
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        status=status,
        networks=[],
        clients=clients,
        vpn_stats=vpn_stats,
        containers=containers,
        qsecbit=qsecbit,
        layer_threats=layer_threats,
        mobile_protection=mobile_protection,
        show_scan_result=False
    )


@app.route('/scan')
def scan():
    """Redirect to WiFi tab - scanning is now done via AJAX."""
    return redirect('/#wifi')


@app.route('/connect', methods=['POST'])
def connect():
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '')

    if not ssid:
        flash('Please enter a network name', 'error')
        return redirect('/#wifi')

    wpa_conf = f'''
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={{
    ssid="{ssid}"
    psk="{password}"
    key_mgmt=WPA-PSK
}}
'''
    try:
        WPA_SUPPLICANT_CONF.parent.mkdir(parents=True, exist_ok=True)
        WPA_SUPPLICANT_CONF.write_text(wpa_conf)
        run_command('wpa_cli -i wlan1 reconfigure')
        flash(f'Connecting to {ssid}...', 'success')
    except Exception as e:
        flash(f'Failed to connect: {e}', 'error')

    return redirect('/#wifi')


@app.route('/hotspot', methods=['POST'])
def hotspot():
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '')

    if not ssid or len(password) < 8:
        flash('Invalid SSID or password (min 8 chars)', 'error')
        return redirect('/#wifi')

    try:
        content = HOSTAPD_CONF.read_text()
        content = re.sub(r'^ssid=.*$', f'ssid={ssid}', content, flags=re.M)
        content = re.sub(r'^wpa_passphrase=.*$', f'wpa_passphrase={password}', content, flags=re.M)
        HOSTAPD_CONF.write_text(content)
        run_command('systemctl reload hostapd')
        flash('Hotspot settings updated', 'success')
    except Exception as e:
        flash(f'Failed to update: {e}', 'error')

    return redirect('/#wifi')


@app.route('/action', methods=['POST'])
def action():
    action = request.form.get('action')

    if action == 'restart_hostapd':
        run_command('systemctl restart hostapd')
        flash('Hotspot restarted', 'success')
    elif action == 'restart_containers':
        run_command('systemctl restart guardian-suricata guardian-zeek guardian-waf guardian-neuro guardian-adguard guardian-xdp guardian-aggregator')
        flash('Containers restarting...', 'success')
    elif action == 'restart_network':
        run_command('systemctl restart networking')
        flash('Network restarted', 'success')
    elif action == 'restart_services':
        run_command('systemctl restart hostapd dnsmasq guardian-suricata guardian-zeek guardian-waf guardian-neuro guardian-adguard guardian-xdp guardian-aggregator guardian-webui')
        flash('All services restarting...', 'success')
    elif action == 'reboot':
        run_command('reboot')
        flash('Rebooting...', 'success')
    elif action == 'restart_adguard':
        run_command('systemctl restart guardian-adguard')
        flash('AdGuard restarting...', 'success')
        return redirect('/#adguard')
    elif action == 'flush_dns':
        # Flush DNS cache by restarting dnsmasq
        run_command('systemctl restart dnsmasq')
        flash('DNS cache flushed', 'success')
        return redirect('/#adguard')

    return redirect('/#system')


@app.route('/api/status')
def api_status():
    return jsonify(get_status())


@app.route('/api/security')
def api_security():
    return jsonify(get_qsecbit_data())


@app.route('/api/containers')
def api_containers():
    return jsonify(get_container_status())


@app.route('/api/scan')
def api_scan():
    return jsonify(scan_wifi())


@app.route('/api/clients')
def api_clients():
    """Get connected clients list."""
    clients = get_connected_clients()
    return jsonify(clients)


@app.route('/api/clients/<mac>/disconnect', methods=['POST'])
def api_client_disconnect(mac):
    """Disconnect a client from the network by MAC address."""
    # Normalize MAC address
    mac = mac.lower().replace('-', ':')

    # Get the hostapd interface
    hostapd_iface = get_hostapd_interface()
    if not hostapd_iface:
        hostapd_iface = 'wlan1'

    # Use hostapd_cli to deauthenticate the client
    output, success = run_command(f'hostapd_cli -i {hostapd_iface} deauthenticate {mac} 2>/dev/null')

    if success or 'OK' in output:
        return jsonify({
            'success': True,
            'message': f'Client {mac} has been disconnected'
        })

    # Try alternative method using iw (for stations not via hostapd)
    output2, success2 = run_command(f'iw dev {hostapd_iface} station del {mac} 2>/dev/null')

    if success2:
        return jsonify({
            'success': True,
            'message': f'Client {mac} has been disconnected'
        })

    return jsonify({
        'success': False,
        'error': f'Failed to disconnect client {mac}. Client may have already disconnected.'
    }), 400


@app.route('/api/vpn')
def api_vpn():
    """Get HTP file transfer statistics."""
    return jsonify(get_vpn_stats())


@app.route('/api/adguard')
def api_adguard():
    """Get AdGuard Home statistics from its API."""
    try:
        import urllib.request
        import urllib.error
        # AdGuard Home API endpoint
        url = 'http://127.0.0.1:3000/control/stats'
        req = urllib.request.Request(url, headers={'User-Agent': 'Guardian/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            import json
            data = json.loads(response.read().decode())
            # Calculate blocked percentage
            total = data.get('num_dns_queries', 0)
            blocked = data.get('num_blocked_filtering', 0)
            if total > 0:
                data['blocked_percent'] = (blocked / total) * 100
            else:
                data['blocked_percent'] = 0
            return jsonify(data)
    except urllib.error.URLError:
        return jsonify({
            'num_dns_queries': 0,
            'num_blocked_filtering': 0,
            'blocked_percent': 0,
            'error': 'AdGuard not reachable'
        })
    except Exception as e:
        return jsonify({
            'num_dns_queries': 0,
            'num_blocked_filtering': 0,
            'blocked_percent': 0,
            'error': str(e)
        })


@app.route('/api/layer_threats')
def api_layer_threats():
    """Get L2-L7 layer threat breakdown."""
    return jsonify(get_layer_threat_data())


@app.route('/api/mobile_protection')
def api_mobile_protection():
    """Get mobile network protection status."""
    return jsonify(get_mobile_protection_data())


@app.route('/api/threats')
def api_threats():
    """Get aggregated threat data."""
    try:
        threat_file = '/var/log/hookprobe/threats/aggregated.json'
        if os.path.exists(threat_file):
            with open(threat_file, 'r') as f:
                return jsonify(json.load(f))
        return jsonify({'error': 'No threat data available', 'stats': {}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/block_ip', methods=['POST'])
def api_block_ip():
    """Block an IP address via XDP."""
    ip = request.form.get('ip') or request.json.get('ip') if request.is_json else None
    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    # Validate IP format
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address format'}), 400

    # Block via XDP
    output, success = run_command(f'python3 /opt/hookprobe/guardian/xdp/xdp_manager.py block {ip}')
    if success:
        return jsonify({'success': True, 'message': f'IP {ip} blocked', 'output': output})
    return jsonify({'error': 'Failed to block IP', 'output': output}), 500


@app.route('/api/unblock_ip', methods=['POST'])
def api_unblock_ip():
    """Unblock an IP address."""
    ip = request.form.get('ip') or request.json.get('ip') if request.is_json else None
    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    # Remove from blocklist via bpftool
    output, success = run_command(f'bpftool map delete name blocklist_map key {ip}')
    if success:
        return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
    return jsonify({'error': 'Failed to unblock IP', 'output': output}), 500


@app.route('/api/xdp_stats')
def api_xdp_stats():
    """Get XDP DDoS protection statistics."""
    output, success = run_command('python3 /opt/hookprobe/guardian/xdp/xdp_manager.py stats')
    if success:
        try:
            return jsonify(json.loads(output))
        except:
            return jsonify({'error': 'Failed to parse XDP stats'})
    return jsonify({'error': 'XDP not available'})


@app.route('/api/security_test', methods=['POST'])
def api_security_test():
    """Run security test suite."""
    target = request.form.get('target', '192.168.4.1')

    # Run test in background and return immediately
    output, success = run_command(
        f'/opt/hookprobe/guardian/simulator/test_security.sh {target} > /var/log/hookprobe/threats/test_output.log 2>&1 &',
        timeout=5
    )
    return jsonify({
        'success': True,
        'message': 'Security test started',
        'log_file': '/var/log/hookprobe/threats/test_output.log',
        'report_file': '/var/log/hookprobe/threats/test_report.json'
    })


@app.route('/api/security_test_result')
def api_security_test_result():
    """Get security test results."""
    report_file = '/var/log/hookprobe/threats/test_report.json'
    log_file = '/var/log/hookprobe/threats/test_output.log'

    result = {'status': 'unknown', 'report': None, 'log': None}

    if os.path.exists(report_file):
        try:
            with open(report_file, 'r') as f:
                result['report'] = json.load(f)
                result['status'] = 'complete'
        except:
            result['status'] = 'error'

    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                result['log'] = f.read()[-5000:]  # Last 5KB
        except:
            pass

    return jsonify(result)


@app.route('/api/service/<service_name>/<action>', methods=['POST'])
def api_service_control(service_name, action):
    """Control Guardian services (start/stop/restart)."""
    allowed_services = [
        'guardian-suricata', 'guardian-zeek', 'guardian-waf',
        'guardian-xdp', 'guardian-aggregator', 'guardian-neuro',
        'guardian-adguard', 'guardian-qsecbit'
    ]

    if service_name not in allowed_services:
        return jsonify({'error': 'Service not allowed'}), 403

    if action not in ['start', 'stop', 'restart', 'status']:
        return jsonify({'error': 'Invalid action'}), 400

    output, success = run_command(f'sudo systemctl {action} {service_name}')

    if action == 'status':
        is_active, _ = run_command(f'systemctl is-active {service_name}')
        return jsonify({'service': service_name, 'active': is_active == 'active', 'output': output})

    return jsonify({'success': success, 'service': service_name, 'action': action, 'output': output})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
