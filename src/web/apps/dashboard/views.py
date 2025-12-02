"""
Dashboard Views - AdminLTE interface
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db import connection
from django.core.cache import cache
import requests
import time
import os
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


# ============================================================================
# Health Check & Monitoring Endpoints
# ============================================================================

@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """
    Health check endpoint for monitoring systems
    Returns JSON with system health status

    Used by:
    - Load balancers
    - Monitoring systems (Grafana, Prometheus)
    - Kubernetes/container orchestrators
    - Nagios/Zabbix

    Returns:
        200: System is healthy
        200: System is degraded (with warning details)
        503: System is unhealthy
    """
    start_time = time.time()

    health_data = {
        "status": "healthy",
        "pod": "001",
        "name": "Web DMZ",
        "version": "5.0",
        "checks": {},
        "metrics": {}
    }

    # Check database connectivity
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        health_data["checks"]["postgres_connection"] = "healthy"
    except Exception as e:
        health_data["checks"]["postgres_connection"] = "unhealthy"
        health_data["status"] = "degraded"
        health_data["checks"]["postgres_error"] = str(e)

    # Check Redis/cache connectivity
    try:
        cache.set('health_check', 'ok', 10)
        result = cache.get('health_check')
        if result == 'ok':
            health_data["checks"]["redis_connection"] = "healthy"
        else:
            health_data["checks"]["redis_connection"] = "degraded"
            health_data["status"] = "degraded"
    except Exception as e:
        health_data["checks"]["redis_connection"] = "unhealthy"
        health_data["status"] = "degraded"
        health_data["checks"]["redis_error"] = str(e)

    # Check disk space
    try:
        import shutil
        stat = shutil.disk_usage('/')
        disk_usage_percent = (stat.used / stat.total) * 100

        if disk_usage_percent < 80:
            health_data["checks"]["disk_space"] = "healthy"
        elif disk_usage_percent < 90:
            health_data["checks"]["disk_space"] = "warning"
            health_data["status"] = "degraded"
        else:
            health_data["checks"]["disk_space"] = "critical"
            health_data["status"] = "unhealthy"

        health_data["metrics"]["disk_usage_percent"] = round(disk_usage_percent, 2)
        health_data["metrics"]["disk_free_gb"] = round(stat.free / (1024**3), 2)
    except Exception as e:
        health_data["checks"]["disk_space"] = "unknown"
        health_data["checks"]["disk_error"] = str(e)

    # Django application health
    health_data["checks"]["django"] = "healthy"

    # Response time
    response_time = time.time() - start_time
    health_data["metrics"]["response_time_ms"] = round(response_time * 1000, 2)

    # Set HTTP status code based on health
    status_code = 200
    if health_data["status"] == "degraded":
        status_code = 200  # Still return 200 for degraded
    elif health_data["status"] == "unhealthy":
        status_code = 503  # Service Unavailable

    return JsonResponse(health_data, status=status_code)


@csrf_exempt
@require_http_methods(["GET"])
def pods_health_aggregator(request):
    """
    Aggregate health check for all PODs
    Returns health status of all deployed PODs

    This endpoint queries all other PODs' health endpoints
    and aggregates the results into a single response.
    """

    pods_status = {
        "status": "healthy",
        "deployment_type": os.getenv("DEPLOYMENT_TYPE", "edge"),
        "version": "5.0",
        "pods": {
            "001": {
                "status": "healthy",
                "name": "Web DMZ",
                "url": "http://10.200.1.12/api/v1/health"
            },
            "002": {
                "status": "unknown",
                "name": "IAM",
                "url": "http://10.200.2.12/health"
            },
            "003": {
                "status": "unknown",
                "name": "Database",
                "url": "http://10.200.3.12/health"
            },
            "004": {
                "status": "unknown",
                "name": "Cache",
                "url": "http://10.200.4.12/health"
            },
            "005": {
                "status": "unknown",
                "name": "Monitoring",
                "url": "http://10.200.5.12/health"
            },
            "006": {
                "status": "unknown",
                "name": "Security",
                "url": "http://10.200.6.12/health"
            },
            "007": {
                "status": "unknown",
                "name": "AI Response",
                "url": "http://10.200.7.12/health"
            },
            "008": {
                "status": "not_deployed",
                "name": "Automation",
                "url": "http://10.200.8.12/health"
            }
        },
        "overall_health": {
            "healthy": 1,
            "degraded": 0,
            "unhealthy": 0,
            "unknown": 6,
            "not_deployed": 1
        }
    }

    # TODO: Actually query other PODs' health endpoints
    # This is a placeholder that returns current POD (001) status only
    # Future enhancement: Use requests library to query http://10.200.X.12/health
    # and update each POD's status based on response

    return JsonResponse(pods_status)


@csrf_exempt
@require_http_methods(["GET"])
def metrics_prometheus(request):
    """
    Metrics endpoint for Prometheus/VictoriaMetrics
    Returns metrics in Prometheus text format

    These metrics can be scraped by:
    - Prometheus
    - VictoriaMetrics
    - Grafana Cloud
    - Datadog
    """
    # TODO: Implement actual metrics collection using django-prometheus or similar
    # For now, return placeholder metrics

    metrics_text = """# HELP hookprobe_web_requests_total Total HTTP requests
# TYPE hookprobe_web_requests_total counter
hookprobe_web_requests_total 0

# HELP hookprobe_web_request_duration_seconds HTTP request duration in seconds
# TYPE hookprobe_web_request_duration_seconds histogram
hookprobe_web_request_duration_seconds_bucket{le="0.1"} 0
hookprobe_web_request_duration_seconds_bucket{le="0.5"} 0
hookprobe_web_request_duration_seconds_bucket{le="1.0"} 0
hookprobe_web_request_duration_seconds_bucket{le="+Inf"} 0
hookprobe_web_request_duration_seconds_sum 0
hookprobe_web_request_duration_seconds_count 0

# HELP hookprobe_web_active_users Currently active users
# TYPE hookprobe_web_active_users gauge
hookprobe_web_active_users 0

# HELP hookprobe_web_database_connections Active database connections
# TYPE hookprobe_web_database_connections gauge
hookprobe_web_database_connections 0

# HELP hookprobe_web_cache_hits_total Cache hits
# TYPE hookprobe_web_cache_hits_total counter
hookprobe_web_cache_hits_total 0

# HELP hookprobe_web_cache_misses_total Cache misses
# TYPE hookprobe_web_cache_misses_total counter
hookprobe_web_cache_misses_total 0
"""

    return HttpResponse(metrics_text, content_type='text/plain')


@csrf_exempt
@require_http_methods(["GET"])
def readiness_check(request):
    """
    Kubernetes-style readiness probe

    Returns:
        200: Application is ready to receive traffic
        503: Application is not ready (still initializing)
    """
    # Check if critical components are available
    try:
        # Check database
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

        # Check cache
        cache.set('readiness_check', 'ok', 5)

        return JsonResponse({"status": "ready"}, status=200)
    except Exception as e:
        return JsonResponse({
            "status": "not_ready",
            "error": str(e)
        }, status=503)


@csrf_exempt
@require_http_methods(["GET"])
def liveness_check(request):
    """
    Kubernetes-style liveness probe

    Returns:
        200: Application is alive (container should not be restarted)
        503: Application is dead (container should be restarted)
    """
    # Simple check - if Django is responding, we're alive
    return JsonResponse({"status": "alive"}, status=200)
