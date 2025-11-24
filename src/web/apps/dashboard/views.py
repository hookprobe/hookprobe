"""
Dashboard Views - AdminLTE interface
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import requests
from django.conf import settings


@login_required
def dashboard_home(request):
    """Main dashboard view with system overview"""

    # Get Qsecbit latest status
    qsecbit_data = get_qsecbit_status()

    # Get device statistics
    from apps.devices.models import Device
    devices_total = Device.objects.count()
    devices_online = Device.objects.filter(status='online').count()
    devices_offline = Device.objects.filter(status='offline').count()
    devices_warning = Device.objects.filter(status='warning').count()

    # Get security events (last 24h)
    from apps.security.models import SecurityEvent
    yesterday = timezone.now() - timedelta(days=1)
    security_events = SecurityEvent.objects.filter(
        timestamp__gte=yesterday
    ).count()

    # Get recent alerts
    recent_alerts = SecurityEvent.objects.filter(
        severity__in=['high', 'critical']
    ).order_by('-timestamp')[:10]

    context = {
        'qsecbit_data': qsecbit_data,
        'devices_total': devices_total,
        'devices_online': devices_online,
        'devices_offline': devices_offline,
        'devices_warning': devices_warning,
        'security_events_24h': security_events,
        'recent_alerts': recent_alerts,
    }

    return render(request, 'admin/dashboard.html', context)


@login_required
def system_status(request):
    """System status overview"""
    # Get POD statuses
    pods_status = check_pods_status()

    context = {
        'pods_status': pods_status,
    }

    return render(request, 'admin/system_status.html', context)


def get_qsecbit_status():
    """Fetch latest Qsecbit status from API"""
    try:
        api_url = settings.HOOKPROBE['QSECBIT_API_URL']
        response = requests.get(f'{api_url}/api/qsecbit/latest', timeout=5)

        if response.status_code == 200:
            data = response.json()
            return {
                'score': data.get('score', 0),
                'rag_status': data.get('rag_status', 'UNKNOWN'),
                'attack_probability': data.get('components', {}).get('attack_probability', 0),
                'drift': data.get('components', {}).get('drift', 0),
                'available': True,
            }
    except Exception as e:
        print(f"Error fetching Qsecbit data: {e}")

    return {
        'score': 0,
        'rag_status': 'UNAVAILABLE',
        'attack_probability': 0,
        'drift': 0,
        'available': False,
    }


def check_pods_status():
    """Check status of HookProbe PODs"""
    pods = [
        {'name': 'POD-001 Web DMZ', 'ip': '10.200.1.12', 'port': 80},
        {'name': 'POD-002 IAM', 'ip': '10.200.2.12', 'port': 3000},
        {'name': 'POD-003 Database', 'ip': '10.200.3.12', 'port': 5432},
        {'name': 'POD-004 Cache', 'ip': '10.200.4.12', 'port': 6379},
        {'name': 'POD-005 Monitoring', 'ip': '10.200.5.12', 'port': 3000},
        {'name': 'POD-006 Security', 'ip': '10.200.6.12', 'port': 8888},
        {'name': 'POD-007 AI Response', 'ip': '10.200.7.12', 'port': 8888},
    ]

    # In a real implementation, check actual POD health
    # For now, return mock data
    for pod in pods:
        pod['status'] = 'online'  # Mock status

    return pods
