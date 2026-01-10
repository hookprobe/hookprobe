"""
AIOCHI Real Data Sources
Provides access to real data from dnsXai, Zeek, Suricata, and system metrics.

This module replaces demo data with live data integration.
"""

import json
import logging
import os
import subprocess
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

# dnsXai API (running in fts-dnsxai container, port-mapped to localhost)
# Note: fts-dnsxai maps port 8080 to 8053 on host
DNSXAI_API_URL = os.environ.get('DNSXAI_API_URL', 'http://127.0.0.1:8053')

# ClickHouse connection (AIOCHI analytics database)
CLICKHOUSE_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CLICKHOUSE_PORT = int(os.environ.get('CLICKHOUSE_PORT', '8123'))
CLICKHOUSE_USER = os.environ.get('CLICKHOUSE_USER', 'aiochi')
CLICKHOUSE_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', 'aiochi_secure_password')
CLICKHOUSE_DB = os.environ.get('CLICKHOUSE_DB', 'aiochi')

# Log paths (fallback - only accessible if volumes mounted)
ZEEK_LOG_DIR = Path('/opt/zeek/logs/current')
SURICATA_EVE_LOG = Path('/var/log/suricata/eve.json')

# System paths
DEVICES_JSON = Path('/opt/hookprobe/fortress/data/devices.json')
DHCP_LEASES = Path('/var/lib/misc/dnsmasq.leases')

# Cache durations
STATS_CACHE_TTL = 30  # seconds
EVENT_CACHE_TTL = 10  # seconds

# Cache storage
_cache: Dict[str, Tuple[datetime, Any]] = {}


def _get_cached(key: str, ttl: int = 30) -> Optional[Any]:
    """Get cached value if not expired."""
    if key in _cache:
        cached_time, cached_value = _cache[key]
        if datetime.now() - cached_time < timedelta(seconds=ttl):
            return cached_value
    return None


def _set_cached(key: str, value: Any):
    """Set cached value."""
    _cache[key] = (datetime.now(), value)


# ============================================================================
# DNSXAI INTEGRATION
# ============================================================================

def get_dnsxai_stats() -> Dict[str, Any]:
    """
    Get real DNS protection statistics from dnsXai API.

    Returns:
        Dict with blocked_today, ads_blocked, trackers_blocked, etc.
    """
    cached = _get_cached('dnsxai_stats', STATS_CACHE_TTL)
    if cached:
        return cached

    try:
        import requests
        resp = requests.get(f'{DNSXAI_API_URL}/api/stats', timeout=2)
        if resp.status_code == 200:
            stats = resp.json()
            result = {
                'blocked_today': stats.get('blocked_queries', 0),
                'total_queries': stats.get('total_queries', 0),
                'ads_blocked': stats.get('ads_blocked', 0),
                'trackers_blocked': stats.get('trackers_blocked', 0),
                'malware_blocked': stats.get('malware_blocked', 0),
                'protection_level': stats.get('protection_level', 3),
                'is_paused': stats.get('paused', False),
                'uptime_hours': stats.get('uptime_hours', 0),
            }
            _set_cached('dnsxai_stats', result)
            return result
    except Exception as e:
        logger.debug(f"Could not fetch dnsXai stats: {e}")

    # Fallback to default values
    return {
        'blocked_today': 0,
        'total_queries': 0,
        'ads_blocked': 0,
        'trackers_blocked': 0,
        'malware_blocked': 0,
        'protection_level': 3,
        'is_paused': False,
        'uptime_hours': 0,
    }


def get_recent_blocked_domains(limit: int = 20) -> List[Dict]:
    """
    Get recently blocked domains from dnsXai.

    Returns:
        List of blocked domain entries.
    """
    cached = _get_cached('blocked_domains', EVENT_CACHE_TTL)
    if cached:
        return cached[:limit]

    try:
        import requests
        resp = requests.get(f'{DNSXAI_API_URL}/api/blocked?limit={limit}', timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            blocked = data.get('blocked', [])
            _set_cached('blocked_domains', blocked)
            return blocked[:limit]
    except Exception as e:
        logger.debug(f"Could not fetch blocked domains: {e}")

    return []


# ============================================================================
# CLICKHOUSE INTEGRATION
# ============================================================================

def _query_clickhouse(query: str) -> List[Dict]:
    """Execute a query against ClickHouse and return results as list of dicts."""
    try:
        import requests
        from urllib.parse import urlencode

        params = {
            'user': CLICKHOUSE_USER,
            'password': CLICKHOUSE_PASSWORD,
            'database': CLICKHOUSE_DB,
        }
        url = f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/?{urlencode(params)}"

        # Request JSON format
        full_query = f"{query} FORMAT JSONEachRow"
        resp = requests.post(url, data=full_query, timeout=5)

        if resp.status_code == 200 and resp.text.strip():
            # Parse JSON lines
            results = []
            for line in resp.text.strip().split('\n'):
                if line.strip():
                    results.append(json.loads(line))
            return results
        return []
    except Exception as e:
        logger.debug(f"ClickHouse query failed: {e}")
        return []


# ============================================================================
# ZEEK DATA FROM CLICKHOUSE
# ============================================================================

def get_zeek_conn_events(limit: int = 50) -> List[Dict]:
    """
    Get recent connection events from ClickHouse (zeek_connections table).

    Returns:
        List of connection event dicts.
    """
    cached = _get_cached('zeek_conn', EVENT_CACHE_TTL)
    if cached:
        return cached[:limit]

    # Try ClickHouse first
    query = f"""
        SELECT
            ts as timestamp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
            service,
            duration,
            orig_bytes + resp_bytes as bytes
        FROM zeek_connections
        ORDER BY ts DESC
        LIMIT {limit}
    """
    results = _query_clickhouse(query)
    if results:
        _set_cached('zeek_conn', results)
        return results

    # Fallback to log file if accessible
    conn_log = ZEEK_LOG_DIR / 'conn.log'
    if not conn_log.exists():
        return []

    try:
        result = subprocess.run(
            ['tail', '-n', str(limit * 2), str(conn_log)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return []

        events = []
        for line in result.stdout.strip().split('\n'):
            if line.startswith('#') or not line.strip():
                continue
            try:
                fields = line.split('\t')
                if len(fields) >= 10:
                    events.append({
                        'timestamp': fields[0],
                        'src_ip': fields[2],
                        'src_port': fields[3],
                        'dst_ip': fields[4],
                        'dst_port': fields[5],
                        'proto': fields[6],
                        'service': fields[7] if len(fields) > 7 else '',
                        'duration': fields[8] if len(fields) > 8 else '',
                        'bytes': fields[9] if len(fields) > 9 else '',
                    })
            except (IndexError, ValueError):
                continue

        _set_cached('zeek_conn', events[:limit])
        return events[:limit]
    except Exception as e:
        logger.debug(f"Could not parse Zeek conn.log: {e}")
        return []


def get_zeek_dns_events(limit: int = 50) -> List[Dict]:
    """
    Get recent DNS queries from ClickHouse (zeek_dns table).

    Returns:
        List of DNS event dicts.
    """
    cached = _get_cached('zeek_dns', EVENT_CACHE_TTL)
    if cached:
        return cached[:limit]

    # Try ClickHouse first
    query = f"""
        SELECT
            ts as timestamp,
            src_ip,
            query,
            qtype,
            rcode
        FROM zeek_dns
        ORDER BY ts DESC
        LIMIT {limit}
    """
    results = _query_clickhouse(query)
    if results:
        _set_cached('zeek_dns', results)
        return results

    # Fallback to log file if accessible
    dns_log = ZEEK_LOG_DIR / 'dns.log'
    if not dns_log.exists():
        return []

    try:
        result = subprocess.run(
            ['tail', '-n', str(limit * 2), str(dns_log)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return []

        events = []
        for line in result.stdout.strip().split('\n'):
            if line.startswith('#') or not line.strip():
                continue
            try:
                fields = line.split('\t')
                if len(fields) >= 9:
                    events.append({
                        'timestamp': fields[0],
                        'src_ip': fields[2],
                        'query': fields[9] if len(fields) > 9 else '',
                        'qtype': fields[13] if len(fields) > 13 else '',
                        'rcode': fields[15] if len(fields) > 15 else '',
                    })
            except (IndexError, ValueError):
                continue

        _set_cached('zeek_dns', events[:limit])
        return events[:limit]
    except Exception as e:
        logger.debug(f"Could not parse Zeek dns.log: {e}")
        return []


# ============================================================================
# SURICATA DATA FROM CLICKHOUSE
# ============================================================================

def get_suricata_alerts(limit: int = 50) -> List[Dict]:
    """
    Get recent IDS alerts from ClickHouse (suricata_alerts table).

    Returns:
        List of alert dicts with severity, message, etc.
    """
    cached = _get_cached('suricata_alerts', EVENT_CACHE_TTL)
    if cached:
        return cached[:limit]

    # Try ClickHouse first
    query = f"""
        SELECT
            timestamp,
            src_ip,
            dest_ip as dst_ip,
            signature,
            severity,
            category,
            action
        FROM suricata_alerts
        ORDER BY timestamp DESC
        LIMIT {limit}
    """
    results = _query_clickhouse(query)
    if results:
        _set_cached('suricata_alerts', results)
        return results

    # Fallback to log file if accessible
    if not SURICATA_EVE_LOG.exists():
        return []

    try:
        result = subprocess.run(
            ['tail', '-n', str(limit * 2), str(SURICATA_EVE_LOG)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return []

        alerts = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    alert_info = event.get('alert', {})
                    alerts.append({
                        'timestamp': event.get('timestamp', ''),
                        'src_ip': event.get('src_ip', ''),
                        'dst_ip': event.get('dest_ip', ''),
                        'signature': alert_info.get('signature', ''),
                        'severity': alert_info.get('severity', 3),
                        'category': alert_info.get('category', ''),
                        'action': alert_info.get('action', ''),
                    })
            except json.JSONDecodeError:
                continue

        _set_cached('suricata_alerts', alerts[:limit])
        return alerts[:limit]
    except Exception as e:
        logger.debug(f"Could not parse Suricata eve.json: {e}")
        return []


# ============================================================================
# DEVICE EVENTS
# ============================================================================

def get_device_events(limit: int = 20) -> List[Dict]:
    """
    Get recent device join/leave events from DHCP and system logs.

    Returns:
        List of device event dicts.
    """
    events = []

    # Try reading DHCP leases
    if DHCP_LEASES.exists():
        try:
            with open(DHCP_LEASES, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        events.append({
                            'timestamp': datetime.fromtimestamp(int(parts[0])).isoformat(),
                            'event_type': 'dhcp_lease',
                            'mac': parts[1].upper(),
                            'ip': parts[2],
                            'hostname': parts[3] if len(parts) > 3 else 'Unknown',
                        })
        except Exception as e:
            logger.debug(f"Could not read DHCP leases: {e}")

    # Sort by timestamp descending
    events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return events[:limit]


# ============================================================================
# SYSTEM METRICS
# ============================================================================

def get_system_performance() -> Dict[str, Any]:
    """
    Get real system performance metrics.

    Returns:
        Dict with health_score, latency, bandwidth, uptime, etc.
    """
    cached = _get_cached('system_perf', STATS_CACHE_TTL)
    if cached:
        return cached

    result = {
        'health_score': 85,
        'health_trend': 'stable',
        'latency_ms': 10,
        'latency_trend': 'good',
        'bandwidth_used_pct': 25,
        'bandwidth_trend': 'normal',
        'uptime_pct': 99.9,
    }

    try:
        # Get network latency (ping gateway)
        gateway = _get_default_gateway()
        if gateway:
            ping_result = subprocess.run(
                ['ping', '-c', '3', '-W', '1', gateway],
                capture_output=True, text=True, timeout=5
            )
            if ping_result.returncode == 0:
                # Parse avg latency from ping output
                match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', ping_result.stdout)
                if match:
                    result['latency_ms'] = float(match.group(1))
                    result['latency_trend'] = 'good' if result['latency_ms'] < 20 else 'normal'
    except Exception:
        pass

    try:
        # Get system uptime
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
            uptime_hours = uptime_seconds / 3600
            result['uptime_hours'] = round(uptime_hours, 1)
            result['uptime_pct'] = 99.9 if uptime_hours > 24 else 95.0
    except Exception:
        pass

    try:
        # Get load average for health score calculation
        with open('/proc/loadavg', 'r') as f:
            load_1min = float(f.read().split()[0])
            # Lower health score if high load
            if load_1min > 4:
                result['health_score'] = 60
                result['health_trend'] = 'degrading'
            elif load_1min > 2:
                result['health_score'] = 75
                result['health_trend'] = 'stable'
    except Exception:
        pass

    _set_cached('system_perf', result)
    return result


def _get_default_gateway() -> Optional[str]:
    """Get default gateway IP address."""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            match = re.search(r'default via ([\d.]+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


# ============================================================================
# AMBIENT STATE CALCULATION
# ============================================================================

def get_ambient_state() -> Dict[str, Any]:
    """
    Calculate ambient security state based on real metrics.

    States:
    - CALM: No active threats, everything green
    - CURIOUS: Learning mode, monitoring new devices
    - ALERT: Active threat detected or blocked

    Returns:
        Dict with state, color, icon, message.
    """
    # Get recent data
    dns_stats = get_dnsxai_stats()
    suricata_alerts = get_suricata_alerts(limit=10)
    system_perf = get_system_performance()

    # Count recent high-severity alerts
    high_severity_alerts = [a for a in suricata_alerts if a.get('severity', 3) <= 2]
    malware_blocked = dns_stats.get('malware_blocked', 0)

    # Determine state
    if high_severity_alerts or malware_blocked > 0:
        state = 'ALERT'
        color = '#f44336'  # Red
        icon = 'fa-shield-exclamation'
        if high_severity_alerts:
            last_alert = high_severity_alerts[0]
            message = f"Blocked threat: {last_alert.get('signature', 'Unknown')[:50]}"
        else:
            message = f"Blocked {malware_blocked} malware connections today"
    elif system_perf.get('health_trend') == 'degrading':
        state = 'CURIOUS'
        color = '#ff9800'  # Orange
        icon = 'fa-magnifying-glass'
        message = "Monitoring network performance"
    else:
        state = 'CALM'
        color = '#4caf50'  # Green
        icon = 'fa-shield-check'
        blocked = dns_stats.get('blocked_today', 0)
        if blocked > 0:
            message = f"All clear. Protected you from {blocked} threats today."
        else:
            message = "Everything is peaceful. Your network is protected."

    # Time-based whisper
    hour = datetime.now().hour
    if 22 <= hour or hour < 6:
        whisper = {
            'phase': '🌙',
            'phase_name': 'Dreaming',
            'message': 'Learning your network patterns while you sleep...'
        }
    elif 6 <= hour < 9:
        whisper = {
            'phase': '☀️',
            'phase_name': 'Awakening',
            'message': 'Good morning! Preparing your network for the day.'
        }
    elif 17 <= hour < 22:
        whisper = {
            'phase': '🌆',
            'phase_name': 'Evening',
            'message': 'Wrapping up the day. Your network is secure.'
        }
    else:
        whisper = {
            'phase': '🛡️',
            'phase_name': 'Watching',
            'message': 'Actively monitoring all connections.'
        }

    return {
        'state': state,
        'color': color,
        'icon': icon,
        'message': message,
        'whisper': whisper,
        'last_alert': high_severity_alerts[0] if high_severity_alerts else None,
    }


# ============================================================================
# NARRATIVE FEED GENERATION
# ============================================================================

def generate_privacy_feed(limit: int = 10) -> Dict[str, Any]:
    """
    Generate real privacy feed from actual events.

    Combines:
    - dnsXai blocked domains
    - Suricata alerts
    - Device events
    - System status

    Returns:
        Dict with events list and counts.
    """
    events = []
    now = datetime.now()
    event_id = 0

    # Get DNS blocking stats
    dns_stats = get_dnsxai_stats()
    blocked_today = dns_stats.get('blocked_today', 0)
    trackers_blocked = dns_stats.get('trackers_blocked', 0)
    ads_blocked = dns_stats.get('ads_blocked', 0)

    # Add DNS protection summary
    if blocked_today > 0:
        event_id += 1
        events.append({
            'id': event_id,
            'time': now.strftime('%I:%M %p'),
            'icon': 'fa-ban',
            'color': 'success',
            'title': 'Privacy Protection Active',
            'narrative': f"Blocked {blocked_today} tracking attempts and {ads_blocked} ads today. Your privacy is protected.",
            'category': 'privacy'
        })

    # Get recent blocked domains for specific events
    blocked_domains = get_recent_blocked_domains(limit=5)
    for domain_event in blocked_domains[:3]:
        event_id += 1
        domain = domain_event.get('domain', 'unknown')
        category = domain_event.get('category', 'tracking')
        events.append({
            'id': event_id,
            'time': domain_event.get('time', now.strftime('%I:%M %p')),
            'icon': 'fa-eye-slash' if category == 'tracking' else 'fa-ban',
            'color': 'info',
            'title': f'Blocked {category.title()}',
            'narrative': f"Blocked '{domain}' - this domain tracks users across websites.",
            'category': 'privacy'
        })

    # Get Suricata alerts
    suricata_alerts = get_suricata_alerts(limit=5)
    for alert in suricata_alerts[:2]:
        event_id += 1
        severity = alert.get('severity', 3)
        color = 'danger' if severity <= 1 else 'warning' if severity <= 2 else 'info'
        events.append({
            'id': event_id,
            'time': _format_timestamp(alert.get('timestamp', '')),
            'icon': 'fa-shield-halved',
            'color': color,
            'title': 'Security Event',
            'narrative': alert.get('signature', 'Blocked suspicious traffic'),
            'category': 'security'
        })

    # Get device events
    device_events = get_device_events(limit=3)
    for dev_event in device_events[:2]:
        event_id += 1
        hostname = dev_event.get('hostname', 'Unknown Device')
        events.append({
            'id': event_id,
            'time': _format_timestamp(dev_event.get('timestamp', '')),
            'icon': 'fa-wifi',
            'color': 'info',
            'title': 'Device Connected',
            'narrative': f"'{hostname}' joined the network.",
            'category': 'device'
        })

    # Add system status
    system_perf = get_system_performance()
    if system_perf.get('health_score', 0) >= 80:
        event_id += 1
        events.append({
            'id': event_id,
            'time': now.strftime('%I:%M %p'),
            'icon': 'fa-shield-check',
            'color': 'success',
            'title': 'All Clear',
            'narrative': "Your network is running smoothly. No threats detected.",
            'category': 'status'
        })

    # Sort by event ID (most recent first) and limit
    events.sort(key=lambda x: x['id'], reverse=True)
    events = events[:limit]

    # Count categories
    categories = {}
    for event in events:
        cat = event.get('category', 'other')
        categories[cat] = categories.get(cat, 0) + 1

    return {
        'events': events,
        'unread_count': min(len(events), 3),
        'categories': categories,
    }


def _format_timestamp(ts: str) -> str:
    """Format timestamp for display."""
    if not ts:
        return datetime.now().strftime('%I:%M %p')

    try:
        # Try ISO format
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime('%I:%M %p')
    except (ValueError, TypeError):
        pass

    try:
        # Try Unix timestamp
        dt = datetime.fromtimestamp(float(ts))
        return dt.strftime('%I:%M %p')
    except (ValueError, TypeError):
        pass

    return ts[:8] if len(ts) > 8 else ts


# ============================================================================
# QUICK ACTIONS STATE
# ============================================================================

def get_quick_actions_state() -> Dict[str, Any]:
    """
    Get current state of quick actions from real system state.

    Returns:
        Dict with actions and their current states.
    """
    dns_stats = get_dnsxai_stats()

    # Privacy mode is based on protection level
    privacy_active = dns_stats.get('protection_level', 3) >= 3

    actions = [
        {
            'id': 'pause_kids',
            'label': "Pause Kids' Internet",
            'icon': 'fa-pause-circle',
            'color': 'warning',
            'active': False,  # Would need to check SDN rules
            'description': "Temporarily block internet for kids' devices"
        },
        {
            'id': 'game_mode',
            'label': 'Game Mode',
            'icon': 'fa-gamepad',
            'color': 'info',
            'active': False,  # Would need to check QoS settings
            'description': "Prioritize gaming traffic for low latency"
        },
        {
            'id': 'privacy_mode',
            'label': 'Privacy Mode',
            'icon': 'fa-user-secret',
            'color': 'primary',
            'active': privacy_active,
            'description': "Block all tracking and analytics domains"
        },
        {
            'id': 'guest_lockdown',
            'label': 'Guest Lockdown',
            'icon': 'fa-lock',
            'color': 'danger',
            'active': False,  # Would need to check VLAN isolation
            'description': "Isolate guest network from main network"
        }
    ]

    return {'actions': actions}


# ============================================================================
# COLOR PALETTE FOR BUBBLES
# ============================================================================

BUBBLE_COLOR_PALETTE = [
    {'name': 'Blue', 'value': '#2196F3', 'icon': 'fa-circle', 'class': 'primary'},
    {'name': 'Green', 'value': '#4CAF50', 'icon': 'fa-circle', 'class': 'success'},
    {'name': 'Orange', 'value': '#FF9800', 'icon': 'fa-circle', 'class': 'warning'},
    {'name': 'Red', 'value': '#f44336', 'icon': 'fa-circle', 'class': 'danger'},
    {'name': 'Purple', 'value': '#9C27B0', 'icon': 'fa-circle', 'class': 'purple'},
    {'name': 'Pink', 'value': '#E91E63', 'icon': 'fa-circle', 'class': 'pink'},
    {'name': 'Cyan', 'value': '#00BCD4', 'icon': 'fa-circle', 'class': 'info'},
    {'name': 'Teal', 'value': '#009688', 'icon': 'fa-circle', 'class': 'teal'},
    {'name': 'Indigo', 'value': '#3F51B5', 'icon': 'fa-circle', 'class': 'indigo'},
    {'name': 'Amber', 'value': '#FFC107', 'icon': 'fa-circle', 'class': 'amber'},
    {'name': 'Grey', 'value': '#607D8B', 'icon': 'fa-circle', 'class': 'secondary'},
    {'name': 'Deep Purple', 'value': '#673AB7', 'icon': 'fa-circle', 'class': 'deep-purple'},
]

BUBBLE_ICON_PALETTE = [
    {'name': 'Users', 'value': 'fa-users', 'label': 'Family'},
    {'name': 'User', 'value': 'fa-user', 'label': 'Person'},
    {'name': 'User Tie', 'value': 'fa-user-tie', 'label': 'Dad'},
    {'name': 'Child', 'value': 'fa-child', 'label': 'Kids'},
    {'name': 'User Friends', 'value': 'fa-user-friends', 'label': 'Guests'},
    {'name': 'Home', 'value': 'fa-home', 'label': 'Smart Home'},
    {'name': 'Laptop', 'value': 'fa-laptop', 'label': 'Work'},
    {'name': 'Briefcase', 'value': 'fa-briefcase', 'label': 'Business'},
    {'name': 'Gamepad', 'value': 'fa-gamepad', 'label': 'Gaming'},
    {'name': 'TV', 'value': 'fa-tv', 'label': 'Entertainment'},
    {'name': 'Layer Group', 'value': 'fa-layer-group', 'label': 'Custom'},
    {'name': 'Shield', 'value': 'fa-shield', 'label': 'Security'},
]


def get_color_palette() -> List[Dict]:
    """Get available colors for bubble customization."""
    return BUBBLE_COLOR_PALETTE


def get_icon_palette() -> List[Dict]:
    """Get available icons for bubble customization."""
    return BUBBLE_ICON_PALETTE
