"""
Security Module Views - QSecBit, Threats, XDP Stats, Block Log, Export
"""
import json
import os
import uuid
from datetime import datetime, timedelta
from flask import jsonify, request, Response
from . import security_bp
from utils import run_command, load_json_file

# Block log file location
BLOCK_LOG_FILE = '/var/log/hookprobe/security/blocks.json'


def get_block_log():
    """Load block log from file or return empty list."""
    if os.path.exists(BLOCK_LOG_FILE):
        try:
            with open(BLOCK_LOG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    # Return demo data if no log exists
    return _get_demo_blocks()


def _get_demo_blocks():
    """Generate demo block data for display."""
    now = datetime.utcnow()
    return [
        {
            'id': 'blk-001',
            'timestamp': (now - timedelta(minutes=5)).isoformat() + 'Z',
            'source_ip': '185.220.101.45',
            'source_port': 45821,
            'dest_port': 22,
            'protocol': 'TCP',
            'action': 'BLOCKED',
            'category': 'Brute Force',
            'severity': 'HIGH',
            'reason': 'SSH brute force attempt detected',
            'detection_method': 'Rate limiting + pattern match',
            'layer': 'L4',
            'details': {
                'attempts': 47,
                'timeframe': '60s',
                'pattern': 'Rapid sequential auth failures',
                'geo': {'country': 'DE', 'asn': 'AS24940'}
            }
        },
        {
            'id': 'blk-002',
            'timestamp': (now - timedelta(minutes=12)).isoformat() + 'Z',
            'source_ip': '45.155.205.233',
            'source_port': 52341,
            'dest_port': 80,
            'protocol': 'TCP',
            'action': 'BLOCKED',
            'category': 'SQL Injection',
            'severity': 'CRITICAL',
            'reason': 'SQL injection payload in HTTP request',
            'detection_method': 'Signature + ML classifier',
            'layer': 'L7',
            'details': {
                'payload_snippet': "' OR 1=1--",
                'uri': '/api/users?id=1',
                'confidence': 0.97,
                'geo': {'country': 'RU', 'asn': 'AS57523'}
            }
        },
        {
            'id': 'blk-003',
            'timestamp': (now - timedelta(minutes=23)).isoformat() + 'Z',
            'source_ip': '94.102.49.190',
            'source_port': 0,
            'dest_port': 0,
            'protocol': 'ICMP',
            'action': 'BLOCKED',
            'category': 'Port Scan',
            'severity': 'MEDIUM',
            'reason': 'ICMP-based host discovery scan',
            'detection_method': 'XDP rate analysis',
            'layer': 'L3',
            'details': {
                'scan_type': 'ping_sweep',
                'packets': 156,
                'geo': {'country': 'NL', 'asn': 'AS202425'}
            }
        },
        {
            'id': 'blk-004',
            'timestamp': (now - timedelta(hours=1)).isoformat() + 'Z',
            'source_ip': '192.241.xxx.xxx',
            'source_port': 38291,
            'dest_port': 443,
            'protocol': 'TCP',
            'action': 'BLOCKED',
            'category': 'TLS Downgrade',
            'severity': 'HIGH',
            'reason': 'TLS downgrade attack attempt',
            'detection_method': 'Protocol analysis',
            'layer': 'L5',
            'details': {
                'attempted_version': 'SSLv3',
                'expected_version': 'TLSv1.3',
                'geo': {'country': 'US', 'asn': 'AS14061'}
            }
        },
        {
            'id': 'blk-005',
            'timestamp': (now - timedelta(hours=2)).isoformat() + 'Z',
            'source_ip': '103.75.201.88',
            'source_port': 44123,
            'dest_port': 53,
            'protocol': 'UDP',
            'action': 'BLOCKED',
            'category': 'DNS Tunnel',
            'severity': 'HIGH',
            'reason': 'DNS tunneling data exfiltration',
            'detection_method': 'dnsXai ML classifier',
            'layer': 'L7',
            'details': {
                'entropy': 0.89,
                'query_length': 187,
                'subdomain_count': 12,
                'geo': {'country': 'CN', 'asn': 'AS4134'}
            }
        }
    ]


@security_bp.route('/blocks')
def api_blocks():
    """Get recent blocked events."""
    try:
        blocks = get_block_log()
        limit = request.args.get('limit', 50, type=int)
        return jsonify({
            'blocks': blocks[:limit],
            'total': len(blocks)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/blocks/<block_id>')
def api_block_detail(block_id):
    """Get detailed info for a specific block."""
    try:
        blocks = get_block_log()
        for block in blocks:
            if block.get('id') == block_id:
                return jsonify(block)
        return jsonify({'error': 'Block not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/blocks/export')
def api_export_blocks():
    """Export blocks in STIX 2.1 or CSV format."""
    try:
        export_format = request.args.get('format', 'stix')
        blocks = get_block_log()

        if export_format == 'csv':
            return _export_csv(blocks)
        else:
            return _export_stix(blocks)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _export_stix(blocks):
    """Export blocks as STIX 2.1 bundle."""
    stix_objects = []
    bundle_id = f"bundle--{uuid.uuid4()}"

    # Create identity for Guardian
    identity_id = f"identity--{uuid.uuid4()}"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": "HookProbe Guardian",
        "identity_class": "system"
    })

    for block in blocks:
        # Create indicator for each block
        indicator_id = f"indicator--{uuid.uuid4()}"
        observed_data_id = f"observed-data--{uuid.uuid4()}"

        # Map severity to STIX confidence
        severity_map = {'LOW': 25, 'MEDIUM': 50, 'HIGH': 75, 'CRITICAL': 95}
        confidence = severity_map.get(block.get('severity', 'MEDIUM'), 50)

        # Create indicator
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "modified": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "name": f"{block.get('category', 'Unknown')} - {block.get('source_ip', 'Unknown')}",
            "description": block.get('reason', ''),
            "indicator_types": [_map_category_to_stix(block.get('category', ''))],
            "pattern": f"[ipv4-addr:value = '{block.get('source_ip', '0.0.0.0')}']",
            "pattern_type": "stix",
            "valid_from": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "confidence": confidence,
            "labels": [block.get('category', 'unknown'), f"layer:{block.get('layer', 'L3')}"],
            "created_by_ref": identity_id
        }
        stix_objects.append(indicator)

        # Create observed-data
        observed = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_data_id,
            "created": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "modified": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "first_observed": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "last_observed": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "number_observed": 1,
            "object_refs": [f"ipv4-addr--{uuid.uuid4()}"],
            "created_by_ref": identity_id
        }
        stix_objects.append(observed)

        # Create sighting linking indicator to observed-data
        sighting = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": f"sighting--{uuid.uuid4()}",
            "created": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "modified": block.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            "sighting_of_ref": indicator_id,
            "observed_data_refs": [observed_data_id],
            "where_sighted_refs": [identity_id],
            "confidence": confidence,
            "created_by_ref": identity_id
        }
        stix_objects.append(sighting)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects
    }

    response = Response(
        json.dumps(bundle, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename=hookprobe-threats-{datetime.utcnow().strftime("%Y%m%d")}.stix.json'
        }
    )
    return response


def _map_category_to_stix(category):
    """Map block category to STIX indicator type."""
    mapping = {
        'Brute Force': 'malicious-activity',
        'SQL Injection': 'malicious-activity',
        'Port Scan': 'anomalous-activity',
        'TLS Downgrade': 'malicious-activity',
        'DNS Tunnel': 'malicious-activity',
        'DDoS': 'malicious-activity',
        'XSS': 'malicious-activity',
        'Malware': 'malicious-activity'
    }
    return mapping.get(category, 'anomalous-activity')


def _export_csv(blocks):
    """Export blocks as CSV."""
    import csv
    from io import StringIO

    output = StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'Timestamp', 'Source IP', 'Source Port', 'Dest Port', 'Protocol',
        'Category', 'Severity', 'Reason', 'Detection Method', 'Layer'
    ])

    for block in blocks:
        writer.writerow([
            block.get('timestamp', ''),
            block.get('source_ip', ''),
            block.get('source_port', ''),
            block.get('dest_port', ''),
            block.get('protocol', ''),
            block.get('category', ''),
            block.get('severity', ''),
            block.get('reason', ''),
            block.get('detection_method', ''),
            block.get('layer', '')
        ])

    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=hookprobe-threats-{datetime.utcnow().strftime("%Y%m%d")}.csv'
        }
    )
    return response


@security_bp.route('/xdp_stats')
def api_xdp_stats():
    """Get XDP/eBPF statistics."""
    import os
    try:
        # Try to get XDP stats from bpftool or custom script
        stats = {
            'mode': 'Not Loaded',
            'interface': 'eth0',
            'drops': 0,
            'packets': 0,
            'bytes': 0,
            'active_rules': 0,
            'drop_rate': 0.0
        }

        # Check if XDP is loaded on eth0
        output, success = run_command(['ip', 'link', 'show', 'eth0'])
        if success and output:
            if 'xdpdrv' in output:
                stats['mode'] = 'XDP-DRV'
            elif 'xdpgeneric' in output:
                stats['mode'] = 'XDP-SKB'
            elif 'xdpoffload' in output:
                stats['mode'] = 'XDP-HW'
            elif 'xdp' in output.lower():
                stats['mode'] = 'XDP-SKB'

        # Get packet stats from /sys/class/net instead of /proc/net/dev
        try:
            stats_dir = '/sys/class/net/eth0/statistics'
            if os.path.exists(stats_dir):
                with open(f'{stats_dir}/rx_packets', 'r') as f:
                    stats['packets'] = int(f.read().strip())
                with open(f'{stats_dir}/rx_bytes', 'r') as f:
                    stats['bytes'] = int(f.read().strip())
                with open(f'{stats_dir}/rx_dropped', 'r') as f:
                    stats['drops'] = int(f.read().strip())

                # Calculate drop rate
                if stats['packets'] > 0:
                    stats['drop_rate'] = round((stats['drops'] / stats['packets']) * 100, 2)
        except (IOError, ValueError):
            pass

        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/qsecbit')
def api_qsecbit():
    """Get current QSecBit score and components."""
    try:
        qsecbit_file = '/var/log/hookprobe/qsecbit/current.json'
        data = load_json_file(qsecbit_file, {
            'score': 0.0,
            'status': 'GREEN',
            'components': {
                'drift': 0.0,
                'p_attack': 0.0,
                'decay': 0.0,
                'q_drift': 0.0,
                'energy_anomaly': 0.0
            },
            'weights': {
                'alpha': 0.25,
                'beta': 0.25,
                'gamma': 0.20,
                'delta': 0.15,
                'epsilon': 0.15
            }
        })
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/block_ip', methods=['POST'])
def api_block_ip():
    """Block an IP address via XDP."""
    from flask import request
    import re

    data = request.get_json() if request.is_json else {}
    ip = data.get('ip') or request.form.get('ip')

    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    # Validate IP format
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address format'}), 400

    try:
        # Add to XDP blocklist
        output, success = run_command(f'/opt/hookprobe/shared/response/xdp-block.sh add {ip}')
        if success:
            return jsonify({'success': True, 'message': f'Blocked {ip}'})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@security_bp.route('/unblock_ip', methods=['POST'])
def api_unblock_ip():
    """Unblock an IP address."""
    from flask import request
    import re

    data = request.get_json() if request.is_json else {}
    ip = data.get('ip') or request.form.get('ip')

    if not ip:
        return jsonify({'error': 'IP address required'}), 400

    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address format'}), 400

    try:
        output, success = run_command(f'/opt/hookprobe/shared/response/xdp-block.sh remove {ip}')
        if success:
            return jsonify({'success': True, 'message': f'Unblocked {ip}'})
        return jsonify({'success': False, 'error': output}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
