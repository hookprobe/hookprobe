"""
Cortex Views - Neural Command Center Integration for MSSP

Provides:
- /cortex/: Full Cortex page with 3D globe
- /cortex/embedded/: Embedded view for dashboard tabs
- /cortex/api/*: API endpoints for mesh data

Phase 1C: Production Integration
"""

import os
import json
import logging
from datetime import datetime, timedelta
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.db.models import Count, Avg, Q

logger = logging.getLogger(__name__)

# Default Cortex server configuration
CORTEX_SERVER_HOST = os.environ.get('CORTEX_HOST', 'localhost')
CORTEX_SERVER_WS_PORT = int(os.environ.get('CORTEX_WS_PORT', '8765'))
CORTEX_SERVER_API_PORT = int(os.environ.get('CORTEX_API_PORT', '8766'))

# Demo mode state (can be toggled via API)
_demo_mode = True


# =============================================================================
# PAGE VIEWS
# =============================================================================

@login_required
def cortex_view(request):
    """
    Full Cortex Neural Command Center page.

    Renders the 3D globe visualization with all mesh nodes and events.
    """
    context = get_cortex_context(request)
    return render(request, 'admin/cortex/index.html', context)


@login_required
def cortex_embedded(request):
    """
    Embedded Cortex view for dashboard tab integration.

    Lighter-weight version for embedding in other dashboard pages.
    """
    context = get_cortex_context(request)
    context['embedded'] = True
    return render(request, 'admin/cortex/embedded.html', context)


@login_required
def cortex_fullscreen(request):
    """
    Fullscreen Cortex view (minimal chrome).
    """
    context = get_cortex_context(request)
    context['fullscreen'] = True
    return render(request, 'admin/cortex/fullscreen.html', context)


def get_cortex_context(request):
    """Build common context for Cortex views."""
    # Get mesh statistics
    mesh_stats = get_mesh_stats()

    return {
        'cortex_ws_url': f'ws://{CORTEX_SERVER_HOST}:{CORTEX_SERVER_WS_PORT}',
        'cortex_api_url': f'http://{CORTEX_SERVER_HOST}:{CORTEX_SERVER_API_PORT}',
        'demo_mode': _demo_mode,
        'mesh_stats': mesh_stats,
        'node_tiers': ['sentinel', 'guardian', 'fortress', 'nexus'],
    }


# =============================================================================
# API VIEWS
# =============================================================================

@csrf_exempt
@require_http_methods(["GET"])
def api_cortex_status(request):
    """
    GET /cortex/api/status/

    Returns Cortex server status and connection info.
    """
    try:
        # Try to query Cortex server status
        import requests
        api_url = f'http://{CORTEX_SERVER_HOST}:{CORTEX_SERVER_API_PORT}/api/status'
        response = requests.get(api_url, timeout=3)

        if response.status_code == 200:
            cortex_status = response.json()
            cortex_status['reachable'] = True
        else:
            cortex_status = {'reachable': False, 'status': 'error'}
    except Exception as e:
        logger.warning(f"Cortex server not reachable: {e}")
        cortex_status = {'reachable': False, 'error': str(e)}

    return JsonResponse({
        'cortex': cortex_status,
        'mssp': {
            'demo_mode': _demo_mode,
            'mesh_stats': get_mesh_stats(),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
    })


@csrf_exempt
@require_http_methods(["GET"])
def api_cortex_nodes(request):
    """
    GET /cortex/api/nodes/

    Returns all managed devices as Cortex-compatible nodes.
    """
    nodes = get_mesh_nodes()

    return JsonResponse({
        'nodes': nodes,
        'count': len(nodes),
        'by_tier': count_by_tier(nodes),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    })


@csrf_exempt
@require_http_methods(["GET"])
def api_cortex_events(request):
    """
    GET /cortex/api/events/

    Returns recent security events in Cortex format.
    """
    limit = int(request.GET.get('limit', 100))
    events = get_security_events(limit=limit)

    return JsonResponse({
        'events': events,
        'count': len(events),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    })


@csrf_exempt
@require_http_methods(["GET"])
def api_cortex_stats(request):
    """
    GET /cortex/api/stats/

    Returns aggregated mesh statistics.
    """
    stats = get_mesh_stats()

    return JsonResponse({
        'stats': stats,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    })


@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_cortex_mode(request):
    """
    GET/POST /cortex/api/mode/

    Get or set demo/live mode.
    """
    global _demo_mode

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            _demo_mode = data.get('demo', True)
            logger.info(f"Cortex mode set to: {'demo' if _demo_mode else 'live'}")
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({
        'demo_mode': _demo_mode,
        'mode': 'demo' if _demo_mode else 'live',
    })


@csrf_exempt
@require_http_methods(["GET"])
def api_cortex_node_detail(request, node_id):
    """
    GET /cortex/api/node/<node_id>/

    Returns detailed information for a specific node.
    """
    try:
        from apps.devices.models import Device

        device = Device.objects.filter(
            Q(serial_number=node_id) | Q(name__icontains=node_id)
        ).first()

        if not device:
            return JsonResponse({'error': 'Node not found'}, status=404)

        return JsonResponse({
            'node': device_to_node(device),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# =============================================================================
# DATA HELPERS
# =============================================================================

def get_mesh_stats():
    """Get aggregated mesh statistics from devices database."""
    stats = {
        'total_nodes': 0,
        'nodes_online': 0,
        'nodes_offline': 0,
        'by_tier': {
            'sentinel': 0,
            'guardian': 0,
            'fortress': 0,
            'nexus': 0,
        },
        'avg_qsecbit': 0.0,
        'threats_24h': 0,
        'threats_blocked_24h': 0,
    }

    try:
        from apps.devices.models import Device
        from apps.security.models import SecurityEvent

        # Device stats
        stats['total_nodes'] = Device.objects.count()
        stats['nodes_online'] = Device.objects.filter(status='online').count()
        stats['nodes_offline'] = Device.objects.filter(status='offline').count()

        # Tier distribution
        tier_mapping = {
            'sentinel': ['sentinel', 'iot'],
            'guardian': ['guardian', 'travel', 'portable'],
            'fortress': ['fortress', 'edge', 'router'],
            'nexus': ['nexus', 'ml', 'ai', 'compute'],
        }

        for tier, keywords in tier_mapping.items():
            count = Device.objects.filter(
                Q(device_type__icontains=keywords[0]) |
                (Q(device_type__icontains=keywords[1]) if len(keywords) > 1 else Q())
            ).count()
            stats['by_tier'][tier] = count

        # Security events (last 24h)
        yesterday = datetime.now() - timedelta(days=1)
        stats['threats_24h'] = SecurityEvent.objects.filter(
            timestamp__gte=yesterday
        ).count()
        stats['threats_blocked_24h'] = SecurityEvent.objects.filter(
            timestamp__gte=yesterday,
            action='blocked'
        ).count()

    except Exception as e:
        logger.warning(f"Error fetching mesh stats: {e}")

    return stats


def get_mesh_nodes():
    """Get all devices as Cortex-compatible node data."""
    nodes = []

    try:
        from apps.devices.models import Device

        for device in Device.objects.all()[:500]:  # Limit to 500 nodes
            nodes.append(device_to_node(device))

    except Exception as e:
        logger.warning(f"Error fetching mesh nodes: {e}")

    return nodes


def device_to_node(device):
    """Convert a Device model instance to Cortex node format."""
    # Map device type to tier
    tier = 'guardian'  # Default
    dtype = device.device_type.lower() if device.device_type else ''
    if 'sentinel' in dtype or 'iot' in dtype:
        tier = 'sentinel'
    elif 'fortress' in dtype or 'edge' in dtype or 'router' in dtype:
        tier = 'fortress'
    elif 'nexus' in dtype or 'ml' in dtype or 'ai' in dtype:
        tier = 'nexus'

    # Determine Qsecbit status
    qsecbit = getattr(device, 'qsecbit_score', 0.0) or 0.0
    if qsecbit < 0.45:
        status = 'green'
    elif qsecbit < 0.70:
        status = 'amber'
    else:
        status = 'red'

    return {
        'id': device.serial_number or f"device-{device.id}",
        'tier': tier,
        'lat': float(device.latitude) if device.latitude else 0.0,
        'lng': float(device.longitude) if device.longitude else 0.0,
        'label': device.name or device.serial_number or f"Device {device.id}",
        'qsecbit': round(qsecbit, 4),
        'status': status,
        'online': device.status == 'online',
        'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None,
    }


def get_security_events(limit=100):
    """Get recent security events in Cortex format."""
    events = []

    try:
        from apps.security.models import SecurityEvent

        for event in SecurityEvent.objects.order_by('-timestamp')[:limit]:
            cortex_event = {
                'id': f"event-{event.id}",
                'type': 'attack_repelled' if event.action == 'blocked' else 'attack_detected',
                'source': {
                    'ip': event.source_ip or 'unknown',
                    'lat': 0.0,  # Would need GeoIP lookup
                    'lng': 0.0,
                    'label': event.source_ip or 'Unknown',
                },
                'target': {
                    'node_id': event.device.serial_number if event.device else 'unknown',
                    'lat': float(event.device.latitude) if event.device and event.device.latitude else 0.0,
                    'lng': float(event.device.longitude) if event.device and event.device.longitude else 0.0,
                    'label': event.device.name if event.device else 'Unknown',
                },
                'attack_type': event.event_type or 'unknown',
                'severity': event.severity or 'medium',
                'timestamp': event.timestamp.isoformat() + 'Z' if event.timestamp else None,
            }
            events.append(cortex_event)

    except Exception as e:
        logger.warning(f"Error fetching security events: {e}")

    return events


def count_by_tier(nodes):
    """Count nodes by tier."""
    counts = {'sentinel': 0, 'guardian': 0, 'fortress': 0, 'nexus': 0}
    for node in nodes:
        tier = node.get('tier', 'sentinel').lower()
        if tier in counts:
            counts[tier] += 1
    return counts
