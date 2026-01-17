"""
SDN API Views

REST API for Guardian devices and FreeRADIUS integration.
"""

import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
import json

from ..models import RegisteredDevice, DeviceCategory, GuardianConfig, NetworkScan
from apps.common.security_utils import mask_mac, mask_ip

logger = logging.getLogger(__name__)


@csrf_exempt
@require_http_methods(['POST'])
def radius_authorize(request):
    """
    RADIUS authorization endpoint for MAC-based VLAN assignment.

    Called by FreeRADIUS via rlm_rest module.
    Returns VLAN assignment for the given MAC address.

    Request body:
    {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "guardian_id": "uuid",
        "nas_ip": "10.0.0.1"
    }

    Response:
    {
        "authorized": true,
        "vlan_id": 10,
        "session_timeout": 86400,
        "attributes": {
            "Tunnel-Type": "VLAN",
            "Tunnel-Medium-Type": "IEEE-802",
            "Tunnel-Private-Group-Id": "10"
        }
    }
    """
    try:
        data = json.loads(request.body)
        mac_address = data.get('mac_address', '').upper().replace('-', ':')
        guardian_id = data.get('guardian_id')

        if not mac_address:
            return JsonResponse({'authorized': False, 'reason': 'Missing MAC address'}, status=400)

        # Look up device by MAC address
        device = RegisteredDevice.objects.filter(
            mac_address=mac_address,
            is_active=True,
            is_blocked=False
        ).first()

        if device:
            # Update last seen
            device.last_seen = timezone.now()
            device.save(update_fields=['last_seen'])

            vlan_id = device.get_vlan_id()
            logger.info(f"RADIUS auth: {mask_mac(mac_address)} -> VLAN {vlan_id} ({device.friendly_name})")

            return JsonResponse({
                'authorized': True,
                'vlan_id': vlan_id,
                'device_name': device.friendly_name,
                'category': device.category.name if device.category else None,
                'session_timeout': 86400,  # 24 hours
                'attributes': {
                    'Tunnel-Type': 'VLAN',
                    'Tunnel-Medium-Type': 'IEEE-802',
                    'Tunnel-Private-Group-Id': str(vlan_id),
                }
            })

        # Check for blocked device
        blocked = RegisteredDevice.objects.filter(
            mac_address=mac_address,
            is_blocked=True
        ).exists()

        if blocked:
            logger.warning(f"RADIUS auth: {mask_mac(mac_address)} BLOCKED")
            return JsonResponse({'authorized': False, 'reason': 'Device blocked'})

        # Unknown device - assign to quarantine VLAN
        quarantine_vlan = 999
        if guardian_id:
            config = GuardianConfig.objects.filter(guardian_id=guardian_id).first()
            if config:
                quarantine_vlan = config.quarantine_vlan

        logger.info(f"RADIUS auth: {mask_mac(mac_address)} -> Quarantine VLAN {quarantine_vlan}")

        return JsonResponse({
            'authorized': True,
            'vlan_id': quarantine_vlan,
            'device_name': 'Unknown Device',
            'category': 'quarantine',
            'session_timeout': 3600,  # 1 hour for unknown devices
            'attributes': {
                'Tunnel-Type': 'VLAN',
                'Tunnel-Medium-Type': 'IEEE-802',
                'Tunnel-Private-Group-Id': str(quarantine_vlan),
            }
        })

    except json.JSONDecodeError:
        return JsonResponse({'authorized': False, 'reason': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.exception(f"RADIUS auth error: {e}")
        return JsonResponse({'authorized': False, 'reason': 'Internal error'}, status=500)


@csrf_exempt
@require_http_methods(['POST'])
def radius_accounting(request):
    """
    RADIUS accounting endpoint.

    Tracks session start/stop and updates device last_seen.
    """
    try:
        data = json.loads(request.body)
        mac_address = data.get('mac_address', '').upper().replace('-', ':')
        acct_status = data.get('acct_status_type', '')
        client_ip = data.get('framed_ip_address')

        device = RegisteredDevice.objects.filter(mac_address=mac_address).first()
        if device:
            device.last_seen = timezone.now()
            if client_ip:
                device.last_ip = client_ip
            device.save(update_fields=['last_seen', 'last_ip'])

        logger.info(f"RADIUS acct: {mask_mac(mac_address)} {acct_status} IP={mask_ip(client_ip) if client_ip else 'N/A'}")
        return JsonResponse({'status': 'ok'})

    except Exception as e:
        logger.exception(f"RADIUS accounting error: {e}")
        return JsonResponse({'status': 'error'}, status=500)


@csrf_exempt
@require_http_methods(['POST'])
def guardian_scan_results(request):
    """
    Receive WiFi scan results from Guardian.

    Request body:
    {
        "guardian_id": "uuid",
        "networks": [
            {
                "ssid": "MyNetwork",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 6,
                "signal": -65,
                "security": "WPA2",
                "frequency": 2437
            }
        ]
    }
    """
    try:
        data = json.loads(request.body)
        guardian_id = data.get('guardian_id')
        networks = data.get('networks', [])

        if not guardian_id:
            return JsonResponse({'error': 'Missing guardian_id'}, status=400)

        # Clear old scans for this guardian
        NetworkScan.objects.filter(guardian_id=guardian_id).delete()

        # Save new scan results
        for network in networks:
            NetworkScan.objects.create(
                guardian_id=guardian_id,
                ssid=network.get('ssid', ''),
                bssid=network.get('bssid', ''),
                channel=network.get('channel', 0),
                signal_strength=network.get('signal', -100),
                security=network.get('security', 'Unknown'),
                frequency=network.get('frequency', 0),
            )

        logger.info(f"Guardian {guardian_id}: received {len(networks)} scan results")
        return JsonResponse({'status': 'ok', 'count': len(networks)})

    except Exception as e:
        logger.exception(f"Scan results error: {e}")
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(['GET'])
def guardian_config(request, guardian_id):
    """
    Get Guardian configuration for setup.

    Returns hostapd, network, and VLAN configuration.
    """
    try:
        config = GuardianConfig.objects.filter(guardian_id=guardian_id).first()
        if not config:
            return JsonResponse({'error': 'Guardian not found'}, status=404)

        # Get VLANs for this guardian
        from ..models import VLAN
        vlans = VLAN.objects.filter(
            guardian_id=guardian_id,
            is_active=True
        ).values('vlan_id', 'name', 'subnet', 'gateway', 'dhcp_start', 'dhcp_end')

        # Get registered devices
        devices = RegisteredDevice.objects.filter(
            guardian_id=guardian_id,
            is_active=True
        ).values('mac_address', 'friendly_name', 'category__default_vlan', 'vlan__vlan_id')

        return JsonResponse({
            'guardian_id': str(guardian_id),
            'config_version': config.config_version,
            'hotspot': {
                'ssid': config.hotspot_ssid,
                'password': config.hotspot_password,
                'channel': config.hotspot_channel,
                'band': config.hotspot_band,
            },
            'upstream': {
                'ssid': config.upstream_ssid,
                'password': config.upstream_password,
                'security': config.upstream_security,
            },
            'bridge': {
                'lan': config.bridge_lan,
                'upstream': config.bridge_upstream,
            },
            'radius': {
                'server': config.radius_server,
                'port': config.radius_port,
                'secret': config.radius_secret,
            },
            'vlans': {
                'management': config.management_vlan,
                'quarantine': config.quarantine_vlan,
                'configured': list(vlans),
            },
            'devices': list(devices),
        })

    except Exception as e:
        logger.exception(f"Guardian config error: {e}")
        return JsonResponse({'error': str(e)}, status=500)
