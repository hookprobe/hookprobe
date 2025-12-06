#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Simple Flask app for on-device configuration.
Runs on http://192.168.4.1:8080

Version: 5.4.0
"""

import os
import subprocess
import json
import re
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template_string, request, redirect, flash, jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration paths
HOSTAPD_CONF = Path('/etc/hostapd/hostapd.conf')
WPA_SUPPLICANT_CONF = Path('/etc/wpa_supplicant/wpa_supplicant-wlan1.conf')
DNSMASQ_CONF = Path('/etc/dnsmasq.d/guardian.conf')
MODE_FILE = Path('/opt/hookprobe/guardian/mode.conf')
NEURO_STATS = Path('/opt/hookprobe/guardian/neuro/stats.json')
QSECBIT_STATS = Path('/opt/hookprobe/guardian/data/stats.json')
QSECBIT_THREATS = Path('/opt/hookprobe/guardian/data/threats.json')
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
    """Get current Guardian mode (basic or sdn)."""
    if MODE_FILE.exists():
        return MODE_FILE.read_text().strip()
    if HOSTAPD_CONF.exists():
        content = HOSTAPD_CONF.read_text()
        if 'dynamic_vlan=1' in content:
            return 'sdn'
    return 'basic'


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


def get_sdn_stats():
    """Get SDN-specific statistics."""
    if get_mode() != 'sdn':
        return None

    stats = {
        'vlans': [],
        'devices': 0,
        'quarantined': 0,
    }

    output, _ = run_command("ip -br link show | grep 'br[0-9]'")
    for line in output.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                stats['vlans'].append({
                    'name': parts[0],
                    'state': parts[1]
                })

    output, _ = run_command('cat /var/lib/misc/dnsmasq.leases 2>/dev/null | wc -l')
    stats['devices'] = int(output) if output.isdigit() else 0

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
            width: 48px;
            height: 48px;
        }
        .header-logo svg {
            width: 100%;
            height: 100%;
            fill: #FEFDFF;
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
        .mode-basic { background: var(--hp-primary); }
        .mode-sdn { background: var(--hp-green); }

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

        /* Data Table */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        .data-table th, .data-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--hp-border);
        }
        .data-table th {
            background: var(--hp-light);
            font-weight: 600;
            color: var(--hp-dark);
        }
        .data-table tr:hover { background: #f9fafb; }

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

        @media (max-width: 600px) {
            .tabs { flex-wrap: nowrap; }
            .tab { padding: 12px 15px; font-size: 14px; }
            .status-grid { grid-template-columns: repeat(2, 1fr); }
            .rag-grid { grid-template-columns: repeat(2, 1fr); }
            .btn-group { flex-direction: column; }
            .btn { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="header-logo">
                <!-- HookProbe Logo SVG -->
                <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" width="100" height="100" viewBox="0 0 860 1080" xml:space="preserve">
                    <g transform="matrix(1 0 0 1 540 540)">
                        <g style="" vector-effect="non-scaling-stroke">
                            <g transform="matrix(1 0 0 1 -104.29 0)">
                                <path style="stroke: none; stroke-width: 1; stroke-dasharray: none; stroke-linecap: round; stroke-dashoffset: 0; stroke-linejoin: round; stroke-miterlimit: 10; fill: rgb(255,255,255); fill-rule: nonzero; opacity: 1;" vector-effect="non-scaling-stroke" transform=" translate(-1393.9, -335.11)" d="M 1579.57 92.7761 C 1595.97 103.495 1611.6 115.212 1626.29 127.878 C 1640.99 140.544 1654.76 154.162 1667.52 168.645 C 1680.27 183.128 1691.99 198.486 1702.6 214.625 C 1713.2 230.763 1722.68 247.687 1730.98 265.305 C 1739.27 282.922 1746.37 301.235 1752.19 320.153 C 1758.02 339.071 1762.56 358.594 1765.74 378.63 C 1768.92 398.666 1770.73 419.216 1771.11 440.185 C 1771.48 461.155 1770.42 482.543 1767.86 504.259 C 1765.3 525.974 1761.23 548.014 1755.61 570.289 C 1749.99 592.564 1742.81 615.073 1734.01 637.726 C 1731.32 644.593 1728.45 651.492 1725.41 658.418 C 1722.37 665.345 1719.15 672.299 1715.74 679.276 C 1712.34 686.253 1708.76 693.253 1704.99 700.272 C 1701.22 707.291 1697.27 714.329 1693.14 721.381 C 1689.01 728.433 1684.69 735.498 1680.19 742.574 C 1675.7 749.65 1671.02 756.736 1666.16 763.828 C 1661.3 770.919 1656.27 778.016 1651.05 785.114 C 1645.84 792.213 1640.44 799.312 1634.87 806.409 C 1629.29 813.506 1623.55 820.599 1617.62 827.685 C 1611.7 834.77 1605.61 841.847 1599.34 848.912 C 1593.07 855.977 1586.63 863.03 1580.02 870.066 C 1573.4 877.103 1566.62 884.121 1559.67 891.118 C 1552.72 898.115 1545.61 905.09 1538.33 912.039 C 1531.05 918.988 1523.62 925.91 1516.02 932.801 C 1508.43 939.693 1500.68 946.553 1492.78 953.378 C 1484.88 960.203 1476.82 966.992 1468.62 973.741 C 1460.41 980.49 1452.07 987.198 1443.58 993.862 C 1435.09 1000.53 1426.47 1007.14 1417.71 1013.71 C 1408.96 1020.28 1400.08 1026.79 1391.07 1033.25 C 1382.06 1026.79 1373.18 1020.28 1364.43 1013.71 C 1355.67 1007.14 1347.05 1000.53 1338.56 993.862 C 1330.07 987.198 1321.73 980.49 1313.52 973.741 C 1305.32 966.992 1297.26 960.203 1289.36 953.378 C 1281.46 946.553 1273.71 939.693 1266.12 932.801 C 1258.52 925.91 1251.09 918.988 1243.81 912.039 C 1236.53 905.09 1229.42 898.115 1222.47 891.118 C 1215.52 884.121 1208.74 877.103 1202.12 870.066 C 1195.51 863.03 1189.07 855.977 1182.8 848.912 C 1176.53 841.847 1170.44 834.77 1164.52 827.685 C 1158.59 820.599 1152.85 813.506 1147.27 806.409 C 1141.7 799.312 1136.3 792.213 1131.09 785.114 C 1125.87 778.016 1120.84 770.919 1115.98 763.828 C 1111.12 756.736 1106.44 749.65 1101.95 742.574 C 1097.45 735.498 1093.13 728.433 1089 721.381 C 1084.87 714.329 1080.92 707.291 1077.15 700.272 C 1073.38 693.253 1069.8 686.253 1066.4 679.276 C 1062.99 672.299 1059.77 665.345 1056.73 658.418 C 1053.69 651.492 1050.82 644.593 1048.13 637.726 C 1039.33 615.073 1032.15 592.564 1026.53 570.289 C 1020.91 548.014 1016.84 525.974 1014.28 504.259 C 1011.72 482.543 1010.66 461.155 1011.03 440.185 C 1011.41 419.216 1013.22 398.666 1016.4 378.63 C 1019.58 358.594 1024.12 339.071 1029.95 320.153 C 1035.77 301.235 1042.87 282.922 1051.16 265.305 C 1059.46 247.687 1068.94 230.763 1079.54 214.625 C 1090.15 198.486 1101.87 183.128 1114.62 168.645 C 1127.38 154.162 1141.15 140.544 1155.85 127.878 C 1170.54 115.212 1186.17 103.495 1202.57 92.7761 C 1218.97 82.0572 1236.23 72.3291 1254.21 63.6303 C 1272.19 54.9315 1290.91 47.2541 1310.2 40.6375 C 1329.5 34.021 1349.37 28.4575 1369.66 24.0002 C 1376.86 22.4479 1384.02 21.0996 1391.14 19.9588 L 1391.06 19.9588 C 1398.19 21.0986 1405.36 22.4468 1412.56 24.0002 C 1432.85 28.4573 1452.72 34.0207 1472.01 40.6372 C 1491.31 47.2536 1509.99 54.9306 1527.94 63.629 C 1545.88 72.3274 1563.11 82.0549 1579.48 92.7732 L 1579.57 92.7761 Z M 1391.14 577.221 C 1457.92 577.221 1512.13 523.011 1512.13 456.229 C 1512.13 389.447 1457.92 335.237 1391.14 335.237 C 1324.36 335.237 1270.15 389.447 1270.15 456.229 C 1270.15 523.011 1324.36 577.221 1391.14 577.221 Z" />
                            </g>
                        </g>
                    </g>
                </svg>
            </div>
            <div class="header-text">
                <h1>HookProbe Guardian</h1>
                <div class="tagline">Protection on the Move</div>
                <div class="subtitle">Secure gateway with IDS/IPS, WAF, lite AI</div>
            </div>
        </div>
        <div class="mode-badge mode-{{ config.mode }}">
            {{ 'SDN Mode' if config.mode == 'sdn' else 'Basic Mode' }}
        </div>
    </div>

    <!-- Tabs Navigation -->
    <div class="tabs">
        <div class="tab active" data-tab="dashboard">Dashboard</div>
        <div class="tab" data-tab="security">Security</div>
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
                    <div style="display: flex; gap: 10px;">
                        <input type="text" id="block-ip-input" placeholder="e.g., 192.168.1.100" style="flex: 1;">
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
                    <div style="display: flex; gap: 10px;">
                        <input type="text" id="test-target" value="192.168.4.1" style="flex: 1;">
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

            {% if config.mode == 'sdn' and sdn_stats %}
            <div class="card">
                <h2>SDN Status</h2>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="value">{{ sdn_stats.vlans|length }}</div>
                        <div class="label">Active VLANs</div>
                    </div>
                    <div class="status-item">
                        <div class="value">{{ sdn_stats.devices }}</div>
                        <div class="label">Total Devices</div>
                    </div>
                </div>
            </div>
            {% endif %}
        </div>
    </div>

    <div class="footer">
        <p>HookProbe Guardian v5.4.0 | Protection on the Move | <a href="https://hookprobe.com" target="_blank">hookprobe.com</a></p>
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


@app.route('/')
def index():
    config = get_current_config()
    status = get_status()
    sdn_stats = get_sdn_stats()
    containers = get_container_status()
    qsecbit = get_qsecbit_data()
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        status=status,
        networks=[],
        sdn_stats=sdn_stats,
        containers=containers,
        qsecbit=qsecbit,
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


@app.route('/api/sdn')
def api_sdn():
    stats = get_sdn_stats()
    if stats:
        return jsonify(stats)
    return jsonify({'error': 'SDN mode not enabled'}), 400


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
