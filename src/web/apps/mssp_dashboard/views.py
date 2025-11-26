"""
MSSP Dashboard Views

Customer-facing SIEM-like dashboard with 5 main tabs:
1. Home - Dashboard metrics from all security tools
2. Endpoints - Geographic device visualization (MapBox)
3. Vulnerabilities - Past/present vulnerabilities with AI mitigation
4. SOAR - Orchestrated playbooks for vulnerability resolution
5. xSOC - Red/Blue team dashboards with n8n integration
"""

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Q, Avg
from django.utils.timezone import now
from datetime import timedelta
from django.conf import settings

from .models import (
    SecurityDevice, SecurityMetric, Vulnerability,
    SOARPlaybook, PlaybookExecution, ThreatIntelligence,
    IndicatorOfCompromise, IoC_Report
)


@login_required
def dashboard_home(request):
    """
    MSSP Dashboard Home - Overview with real-time metrics.

    Displays aggregated statistics from:
    - Suricata IDS/IPS
    - Zeek network analysis
    - OpenFlow SDN
    - XDP packet processing
    - eBPF system monitoring
    """

    # Get customer's devices
    devices = SecurityDevice.objects.filter(customer=request.user)

    # Device statistics
    total_devices = devices.count()
    online_devices = devices.filter(status='online').count()
    offline_devices = devices.filter(status='offline').count()
    degraded_devices = devices.filter(status='degraded').count()

    # Recent metrics (last 24 hours)
    last_24h = now() - timedelta(hours=24)
    recent_metrics = SecurityMetric.objects.filter(
        device__customer=request.user,
        timestamp__gte=last_24h
    )

    # Alert statistics by severity
    critical_alerts = recent_metrics.filter(severity='critical').count()
    high_alerts = recent_metrics.filter(severity='high').count()
    medium_alerts = recent_metrics.filter(severity='medium').count()
    low_alerts = recent_metrics.filter(severity='low').count()

    # Vulnerability statistics
    open_vulnerabilities = Vulnerability.objects.filter(
        customer=request.user,
        status='open'
    ).count()
    critical_vulnerabilities = Vulnerability.objects.filter(
        customer=request.user,
        status='open',
        severity='critical'
    ).count()

    # Metrics by source tool (last 24h)
    tool_metrics = recent_metrics.values('source_tool').annotate(count=Count('id'))

    # Recent critical events
    critical_events = recent_metrics.filter(
        severity__in=['critical', 'high']
    ).order_by('-timestamp')[:10]

    # Threat intelligence feed
    recent_threats = ThreatIntelligence.objects.all()[:5]

    context = {
        # Device stats
        'total_devices': total_devices,
        'online_devices': online_devices,
        'offline_devices': offline_devices,
        'degraded_devices': degraded_devices,

        # Alert stats
        'critical_alerts': critical_alerts,
        'high_alerts': high_alerts,
        'medium_alerts': medium_alerts,
        'low_alerts': low_alerts,
        'total_alerts': critical_alerts + high_alerts + medium_alerts + low_alerts,

        # Vulnerability stats
        'open_vulnerabilities': open_vulnerabilities,
        'critical_vulnerabilities': critical_vulnerabilities,

        # Tool metrics
        'tool_metrics': tool_metrics,

        # Recent data
        'critical_events': critical_events,
        'recent_threats': recent_threats,
    }

    return render(request, 'mssp_dashboard/home.html', context)


@login_required
def endpoints_map(request):
    """
    Endpoints Tab - Geographic device visualization using MapBox.

    Displays all customer devices on an interactive map with:
    - Device locations
    - Real-time status indicators
    - Device type icons
    - Click for device details
    """

    devices = SecurityDevice.objects.filter(customer=request.user)

    # MapBox configuration
    mapbox_config = {
        'access_token': getattr(settings, 'MAPBOX_ACCESS_TOKEN', ''),
        'style_url': getattr(settings, 'MAPBOX_STYLE_URL', 'mapbox://styles/mapbox/dark-v11'),
        'default_center': [-98.5795, 39.8283],  # Center of USA
        'default_zoom': 4,
    }

    context = {
        'devices': devices,
        'mapbox_config': mapbox_config,
    }

    return render(request, 'mssp_dashboard/endpoints.html', context)


@login_required
def endpoints_geojson(request):
    """
    API endpoint returning devices as GeoJSON for MapBox rendering.
    """

    devices = SecurityDevice.objects.filter(customer=request.user)

    features = []
    for device in devices:
        features.append({
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': [device.longitude, device.latitude]
            },
            'properties': {
                'id': device.id,
                'name': device.name,
                'device_type': device.device_type,
                'status': device.status,
                'ip_address': device.ip_address,
                'location_name': device.location_name,
                'last_seen': device.last_seen.isoformat(),
                'is_online': device.is_online,
            }
        })

    geojson = {
        'type': 'FeatureCollection',
        'features': features
    }

    return JsonResponse(geojson)


@login_required
def vulnerabilities_list(request):
    """
    Vulnerabilities Tab - Past and present vulnerabilities with AI recommendations.

    Displays:
    - Vulnerability list with filtering
    - CVE information
    - CVSS scores
    - AI-powered mitigation recommendations
    - Affected devices
    - Status tracking
    """

    # Filter parameters
    status_filter = request.GET.get('status', 'open')
    severity_filter = request.GET.get('severity', '')

    vulnerabilities = Vulnerability.objects.filter(customer=request.user)

    if status_filter and status_filter != 'all':
        vulnerabilities = vulnerabilities.filter(status=status_filter)

    if severity_filter:
        vulnerabilities = vulnerabilities.filter(severity=severity_filter)

    vulnerabilities = vulnerabilities.prefetch_related('affected_devices')

    # Statistics
    total_vulns = Vulnerability.objects.filter(customer=request.user).count()
    open_vulns = Vulnerability.objects.filter(customer=request.user, status='open').count()
    critical_vulns = Vulnerability.objects.filter(customer=request.user, severity='critical', status='open').count()

    context = {
        'vulnerabilities': vulnerabilities,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
        'total_vulns': total_vulns,
        'open_vulns': open_vulns,
        'critical_vulns': critical_vulns,
    }

    return render(request, 'mssp_dashboard/vulnerabilities.html', context)


@login_required
def vulnerability_detail(request, vuln_id):
    """
    Vulnerability detail view with AI recommendations and remediation options.
    """

    vulnerability = get_object_or_404(Vulnerability, id=vuln_id, customer=request.user)

    # Get recent playbook executions for this vulnerability
    recent_executions = PlaybookExecution.objects.filter(
        vulnerability=vulnerability
    ).order_by('-started_at')[:5]

    # Available playbooks for remediation
    available_playbooks = SOARPlaybook.objects.filter(
        status='active',
        trigger_on_vulnerability=True
    )

    context = {
        'vulnerability': vulnerability,
        'recent_executions': recent_executions,
        'available_playbooks': available_playbooks,
    }

    return render(request, 'mssp_dashboard/vulnerability_detail.html', context)


@login_required
def soar_playbooks(request):
    """
    SOAR Tab - Security Orchestration, Automation and Response.

    Displays:
    - Available playbooks
    - Execution history
    - Success rates
    - Playbook creation/management
    """

    # Get all active playbooks
    playbooks = SOARPlaybook.objects.filter(
        created_by=request.user
    ).order_by('-created_at')

    # Recent executions
    recent_executions = PlaybookExecution.objects.filter(
        playbook__created_by=request.user
    ).order_by('-started_at')[:20]

    # Statistics
    total_playbooks = playbooks.count()
    active_playbooks = playbooks.filter(status='active').count()
    total_executions = PlaybookExecution.objects.filter(playbook__created_by=request.user).count()
    successful_executions = PlaybookExecution.objects.filter(
        playbook__created_by=request.user,
        status='success'
    ).count()

    context = {
        'playbooks': playbooks,
        'recent_executions': recent_executions,
        'total_playbooks': total_playbooks,
        'active_playbooks': active_playbooks,
        'total_executions': total_executions,
        'successful_executions': successful_executions,
    }

    return render(request, 'mssp_dashboard/soar.html', context)


@login_required
def xsoc_dashboard(request):
    """
    xSOC Tab - Red/Blue Team Dashboards with n8n automation + IoC Reporting.

    Displays:
    - Red Team: Attack simulation results
    - Blue Team: Defense metrics
    - Threat intelligence feed
    - IoC Reporting: Unified view from all security vectors
    - n8n workflow integration
    """

    # Get threat intelligence
    threats = ThreatIntelligence.objects.all().order_by('-published_at')[:20]

    # Recent security metrics grouped by threat type
    last_7d = now() - timedelta(days=7)
    last_24h = now() - timedelta(hours=24)
    threat_metrics = SecurityMetric.objects.filter(
        device__customer=request.user,
        timestamp__gte=last_7d,
        metric_type='threat'
    ).values('severity').annotate(count=Count('id'))

    # Playbook automation statistics
    automated_responses = PlaybookExecution.objects.filter(
        playbook__created_by=request.user,
        started_at__gte=last_7d
    ).count()

    # ============================================================================
    # IoC REPORTING - Aggregation from ALL security vectors
    # ============================================================================

    # Get all active IoCs for this customer
    all_iocs = IndicatorOfCompromise.objects.filter(
        customer=request.user,
        is_active=True,
        is_false_positive=False
    )

    # Recent IoCs (last 24 hours)
    recent_iocs = all_iocs.filter(last_seen__gte=last_24h).order_by('-last_seen')[:20]

    # High-confidence IoCs (detected by 3+ systems or confidence > 80)
    high_confidence_iocs = all_iocs.filter(
        Q(detection_count__gte=3) | Q(confidence_score__gt=80)
    ).order_by('-confidence_score', '-last_seen')[:10]

    # Critical IoCs by severity
    critical_iocs = all_iocs.filter(severity='critical').count()
    high_iocs = all_iocs.filter(severity='high').count()
    medium_iocs = all_iocs.filter(severity='medium').count()

    # IoCs by type distribution
    ioc_by_type = all_iocs.values('ioc_type').annotate(count=Count('id')).order_by('-count')

    # IoCs by detection source (which system detected it)
    detection_sources = {
        'QSECBIT': all_iocs.filter(detected_by_qsecbit=True).count(),
        'OpenFlow': all_iocs.filter(detected_by_openflow=True).count(),
        'Suricata': all_iocs.filter(detected_by_suricata=True).count(),
        'Snort': all_iocs.filter(detected_by_snort=True).count(),
        'Zeek': all_iocs.filter(detected_by_zeek=True).count(),
        'XDP': all_iocs.filter(detected_by_xdp=True).count(),
        'eBPF': all_iocs.filter(detected_by_ebpf=True).count(),
        'SIEM': all_iocs.filter(detected_by_siem=True).count(),
        'Threat Intel': all_iocs.filter(detected_by_threat_intel=True).count(),
    }

    # Get active IoC reports
    active_reports = IoC_Report.objects.filter(
        customer=request.user,
        status__in=['draft', 'active']
    ).order_by('-severity', '-created_at')[:10]

    # Recent closed reports
    recent_closed_reports = IoC_Report.objects.filter(
        customer=request.user,
        status='resolved'
    ).order_by('-updated_at')[:5]

    # Overall risk score (average of all active high-risk IoCs)
    high_risk_iocs = all_iocs.filter(
        Q(severity='critical') | Q(severity='high')
    )
    if high_risk_iocs.exists():
        risk_scores = [ioc.risk_score for ioc in high_risk_iocs]
        overall_risk = sum(risk_scores) / len(risk_scores)
    else:
        overall_risk = 0

    # IoC correlation - IoCs that appear together frequently
    correlated_iocs = []
    for ioc in recent_iocs[:5]:
        if ioc.related_iocs.exists():
            correlated_iocs.append({
                'primary': ioc,
                'related': ioc.related_iocs.all()[:3]
            })

    context = {
        # Existing data
        'threats': threats,
        'threat_metrics': threat_metrics,
        'automated_responses': automated_responses,

        # IoC Reporting Data
        'total_iocs': all_iocs.count(),
        'recent_iocs': recent_iocs,
        'high_confidence_iocs': high_confidence_iocs,
        'critical_iocs_count': critical_iocs,
        'high_iocs_count': high_iocs,
        'medium_iocs_count': medium_iocs,
        'ioc_by_type': ioc_by_type,
        'detection_sources': detection_sources,
        'active_reports': active_reports,
        'recent_closed_reports': recent_closed_reports,
        'overall_risk_score': round(overall_risk, 2),
        'correlated_iocs': correlated_iocs,
    }

    return render(request, 'mssp_dashboard/xsoc.html', context)
