#!/usr/bin/env python3
"""
HookProbe Guardian - Local Web UI

Simple Flask app for on-device configuration.
Runs on http://192.168.4.1:8080

Version: 5.2.0
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
    """Get current system status with dynamic interface detection."""
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

    # Determine which interface is hotspot (AP) and which is upstream (managed)
    # Priority: 1) Check hostapd.conf for configured interface
    #           2) Check actual interface type (AP vs managed)
    #           3) Fallback to naming convention

    hostapd_iface = get_hostapd_interface()
    hotspot_interface = None
    upstream_interface = None

    # First pass: Find AP interface (either from hostapd config or actual type)
    for iface, info in all_interfaces.items():
        if hostapd_iface and iface == hostapd_iface:
            hotspot_interface = info
        elif info['type'] == 'AP':
            if not hotspot_interface:
                hotspot_interface = info

    # Second pass: Find upstream (managed) interface
    for iface, info in all_interfaces.items():
        if info['type'] == 'managed':
            # Don't use the same interface as hotspot
            if not hotspot_interface or info['interface'] != hotspot_interface['interface']:
                upstream_interface = info
                break

    # Fallback: If we couldn't determine interfaces, use whatever we have
    if not hotspot_interface and not upstream_interface:
        # Just use first two interfaces found
        iface_list = list(all_interfaces.values())
        if len(iface_list) >= 1:
            hotspot_interface = iface_list[0]
        if len(iface_list) >= 2:
            upstream_interface = iface_list[1]

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

    status['hotspot_interface'] = hotspot_interface or empty_interface
    status['upstream_interface'] = upstream_interface or empty_interface

    # Legacy compatibility fields
    status['wlan0'] = all_interfaces.get('wlan0', empty_interface)
    status['wlan1'] = all_interfaces.get('wlan1', empty_interface)

    # Determine connection status
    status['upstream_connected'] = (
        status['upstream_interface']['type'] == 'managed' and
        status['upstream_interface'].get('connected', False)
    )
    status['hotspot_active'] = status['hotspot_interface']['type'] == 'AP'

    output, _ = run_command('hostname -I')
    status['ip_addresses'] = output.split()

    output, _ = run_command('systemctl is-active hostapd')
    status['hostapd'] = output == 'active'

    output, _ = run_command('systemctl is-active dnsmasq')
    status['dnsmasq'] = output == 'active'

    # Get connected clients from AP interface
    ap_iface = status['hotspot_interface']['interface']
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
    """Get status of all security containers."""
    containers = {
        'suricata': {'name': 'guardian-suricata', 'label': 'Suricata IDS', 'running': False},
        'waf': {'name': 'guardian-waf', 'label': 'ModSecurity WAF', 'running': False},
        'neuro': {'name': 'guardian-neuro', 'label': 'Neuro Protocol', 'running': False},
        'adguard': {'name': 'guardian-adguard', 'label': 'AdGuard Home', 'running': False},
    }

    output, _ = run_command('podman ps --format "{{.Names}}" 2>/dev/null')
    running = output.split('\n') if output else []

    for key, container in containers.items():
        container['running'] = container['name'] in running
        svc_output, _ = run_command(f'systemctl is-active {container["name"]}')
        container['service_active'] = svc_output == 'active'

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
    <title>HookProbe Guardian</title>
    <style>
        :root {
            --hp-primary: #2563eb;
            --hp-primary-dark: #1d4ed8;
            --hp-green: #10b981;
            --hp-amber: #f59e0b;
            --hp-red: #ef4444;
            --hp-dark: #1f2937;
            --hp-light: #f3f4f6;
            --hp-border: #e5e7eb;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--hp-light);
            min-height: 100vh;
        }

        .header {
            background: linear-gradient(135deg, var(--hp-dark) 0%, #374151 100%);
            color: white;
            padding: 20px;
            text-align: center;
        }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header .subtitle { font-size: 14px; opacity: 0.8; }
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
        <h1>HookProbe Guardian</h1>
        <div class="subtitle">Portable SDN Security Gateway</div>
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
                        <span class="badge {% if status.hotspot_active %}badge-success{% else %}badge-danger{% endif %}">
                            {% if status.hotspot_active %}Broadcasting{% else %}Stopped{% endif %}
                        </span>
                        <div class="label">Hotspot ({{ status.hotspot_interface.interface }})</div>
                        <div style="font-size: 11px; color: #6b7280; margin-top: 4px;">
                            {{ status.hotspot_interface.ssid or config.hotspot_ssid }}
                        </div>
                    </div>
                    <div class="status-item">
                        <span class="badge {% if status.upstream_connected %}badge-success{% else %}badge-warning{% endif %}">
                            {% if status.upstream_connected %}Connected{% else %}Disconnected{% endif %}
                        </span>
                        <div class="label">Upstream ({{ status.upstream_interface.interface }})</div>
                        <div style="font-size: 11px; color: #6b7280; margin-top: 4px;">
                            {% if status.upstream_connected %}
                                {{ status.upstream_interface.ssid or 'Unknown' }}
                            {% else %}
                                Not connected
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
                            <strong>Hotspot:</strong>
                            {{ status.hotspot_interface.interface }}
                            ({{ status.hotspot_interface.type | upper }})
                            {% if status.hotspot_interface.is_builtin %}- Built-in{% else %}- USB{% endif %}
                        </div>
                        <div>
                            <strong>Upstream:</strong>
                            {{ status.upstream_interface.interface }}
                            ({{ status.upstream_interface.type | upper }})
                            {% if status.upstream_interface.is_builtin %}- Built-in{% else %}- USB{% endif %}
                        </div>
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
                        <a href="/scan#wifi" class="btn btn-secondary">Scan Networks</a>
                    </div>
                </form>

                {% if networks %}
                <h3>Available Networks ({{ networks|length }})</h3>
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
                        {% for net in networks %}
                        <tr style="cursor: pointer;" onclick="document.getElementById('upstream-ssid').value='{{ net.ssid }}'">
                            <td><strong>{{ net.ssid }}</strong></td>
                            <td>{{ net.signal }} dBm</td>
                            <td>{{ net.channel or 'N/A' }}</td>
                            <td>{{ net.security or 'Open' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% elif show_scan_result %}
                <h3>Scan Results</h3>
                <p style="color: #6b7280;">No networks found. Try scanning again.</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>Interface Status</h2>

                <!-- Summary of detected interfaces -->
                <div style="margin-bottom: 20px; padding: 12px; background: var(--hp-light); border-radius: 8px;">
                    <strong>Detected Interfaces:</strong>
                    {% if status.wireless_interfaces %}
                        {{ status.wireless_interfaces | join(', ') }}
                    {% else %}
                        wlan0, wlan1 (default)
                    {% endif %}
                </div>

                <h3>Hotspot Interface ({{ status.hotspot_interface.interface }})</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">
                            <span class="badge {% if status.hotspot_interface.type == 'AP' %}badge-success{% else %}badge-warning{% endif %}">
                                {{ status.hotspot_interface.type | upper }}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Hardware</div>
                        <div class="value">
                            {% if status.hotspot_interface.is_builtin %}
                                Built-in WiFi
                            {% else %}
                                USB Dongle
                            {% endif %}
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Driver</div>
                        <div class="value">{{ status.hotspot_interface.driver or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">SSID</div>
                        <div class="value">{{ status.hotspot_interface.ssid or config.hotspot_ssid }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Channel</div>
                        <div class="value">{{ status.hotspot_interface.channel or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">TX Power</div>
                        <div class="value">{{ status.hotspot_interface.tx_power or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">MAC Address</div>
                        <div class="value">{{ status.hotspot_interface.mac or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Connected Clients</div>
                        <div class="value">{{ status.clients }}</div>
                    </div>
                </div>

                <h3>Upstream Interface ({{ status.upstream_interface.interface }})</h3>
                <div class="param-grid">
                    <div class="param-item">
                        <div class="label">Mode</div>
                        <div class="value">
                            <span class="badge {% if status.upstream_interface.type == 'managed' %}badge-success{% else %}badge-warning{% endif %}">
                                {{ status.upstream_interface.type | upper }}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Hardware</div>
                        <div class="value">
                            {% if status.upstream_interface.is_builtin %}
                                Built-in WiFi
                            {% else %}
                                USB Dongle
                            {% endif %}
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">Driver</div>
                        <div class="value">{{ status.upstream_interface.driver or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Status</div>
                        <div class="value">
                            <span class="badge {% if status.upstream_connected %}badge-success{% else %}badge-danger{% endif %}">
                                {% if status.upstream_connected %}Connected{% else %}Disconnected{% endif %}
                            </span>
                        </div>
                    </div>
                    <div class="param-item">
                        <div class="label">SSID</div>
                        <div class="value">{{ status.upstream_interface.ssid or 'Not connected' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Signal</div>
                        <div class="value">{{ status.upstream_interface.signal or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">Channel</div>
                        <div class="value">{{ status.upstream_interface.channel or 'N/A' }}</div>
                    </div>
                    <div class="param-item">
                        <div class="label">MAC Address</div>
                        <div class="value">{{ status.upstream_interface.mac or 'N/A' }}</div>
                    </div>
                </div>

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
        <p>HookProbe Guardian v5.2.0 | <a href="https://hookprobe.com" target="_blank">hookprobe.com</a></p>
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

        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
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
    config = get_current_config()
    status = get_status()
    sdn_stats = get_sdn_stats()
    containers = get_container_status()
    qsecbit = get_qsecbit_data()
    networks = scan_wifi()
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        status=status,
        networks=networks,
        sdn_stats=sdn_stats,
        containers=containers,
        qsecbit=qsecbit,
        show_scan_result=True
    )


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
        run_command('systemctl restart guardian-suricata guardian-waf guardian-neuro guardian-adguard')
        flash('Containers restarting...', 'success')
    elif action == 'restart_network':
        run_command('systemctl restart networking')
        flash('Network restarted', 'success')
    elif action == 'restart_services':
        run_command('systemctl restart hostapd dnsmasq guardian-suricata guardian-waf guardian-neuro guardian-adguard guardian-webui')
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
