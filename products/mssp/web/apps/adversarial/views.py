"""
Adversarial Security Framework - Views

"One node's detection → Everyone's protection"

Dashboard views for the adversarial security testing framework.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Count, Avg, Q
from datetime import timedelta
import json

from .models import (
    AdversarialTest,
    Vulnerability,
    Mitigation,
    DesignerAlert,
    TestSchedule,
    VulnerabilitySeverity,
    TestStatus,
)


def is_staff(user):
    """Check if user is staff."""
    return user.is_staff


@login_required
@user_passes_test(is_staff)
def dashboard(request):
    """
    Main adversarial security dashboard.

    Shows overview of:
    - Recent test results
    - Active vulnerabilities
    - Pending mitigations
    - Designer alerts
    """
    # Summary statistics
    total_tests = AdversarialTest.objects.count()
    recent_tests = AdversarialTest.objects.filter(
        scheduled_at__gte=timezone.now() - timedelta(days=30)
    ).count()

    active_vulns = Vulnerability.objects.filter(
        is_mitigated=False, is_false_positive=False
    )
    critical_vulns = active_vulns.filter(severity=VulnerabilitySeverity.CRITICAL).count()
    high_vulns = active_vulns.filter(severity=VulnerabilitySeverity.HIGH).count()

    pending_mitigations = Mitigation.objects.filter(is_implemented=False).count()
    unack_alerts = DesignerAlert.objects.filter(is_acknowledged=False).count()

    # Recent tests
    recent_test_list = AdversarialTest.objects.all()[:5]

    # Top vulnerabilities by CVSS
    top_vulns = Vulnerability.objects.filter(
        is_mitigated=False, is_false_positive=False
    ).order_by('-cvss_score')[:5]

    # Unacknowledged alerts
    alerts = DesignerAlert.objects.filter(is_acknowledged=False)[:5]

    # Calculate risk score
    avg_cvss = active_vulns.aggregate(avg=Avg('cvss_score'))['avg'] or 0
    risk_score = min(100, int(
        (critical_vulns * 30) + (high_vulns * 15) + (avg_cvss * 5)
    ))

    context = {
        'total_tests': total_tests,
        'recent_tests': recent_tests,
        'active_vulns_count': active_vulns.count(),
        'critical_vulns': critical_vulns,
        'high_vulns': high_vulns,
        'pending_mitigations': pending_mitigations,
        'unack_alerts': unack_alerts,
        'recent_test_list': recent_test_list,
        'top_vulns': top_vulns,
        'alerts': alerts,
        'risk_score': risk_score,
        'avg_cvss': round(avg_cvss, 1),
    }

    return render(request, 'adversarial/dashboard.html', context)


@login_required
@user_passes_test(is_staff)
def tests_list(request):
    """List all adversarial tests with filtering."""
    status_filter = request.GET.get('status', '')
    component_filter = request.GET.get('component', '')

    tests = AdversarialTest.objects.all()

    if status_filter:
        tests = tests.filter(status=status_filter)
    if component_filter:
        tests = tests.filter(target_component=component_filter)

    tests = tests.order_by('-scheduled_at')

    # Get unique components for filter dropdown
    components = AdversarialTest.objects.values_list(
        'target_component', flat=True
    ).distinct()

    context = {
        'tests': tests,
        'status_filter': status_filter,
        'component_filter': component_filter,
        'components': components,
        'status_choices': TestStatus.choices,
    }

    return render(request, 'adversarial/tests_list.html', context)


@login_required
@user_passes_test(is_staff)
def test_detail(request, test_id):
    """View details of a specific test."""
    test = get_object_or_404(AdversarialTest, id=test_id)
    vulnerabilities = test.vulnerabilities.all()
    alerts = test.alerts.all()

    context = {
        'test': test,
        'vulnerabilities': vulnerabilities,
        'alerts': alerts,
    }

    return render(request, 'adversarial/test_detail.html', context)


@login_required
@user_passes_test(is_staff)
def vulnerabilities_list(request):
    """List all vulnerabilities with filtering."""
    severity_filter = request.GET.get('severity', '')
    status_filter = request.GET.get('status', '')

    vulns = Vulnerability.objects.all()

    if severity_filter:
        vulns = vulns.filter(severity=severity_filter)
    if status_filter == 'active':
        vulns = vulns.filter(is_mitigated=False, is_false_positive=False)
    elif status_filter == 'mitigated':
        vulns = vulns.filter(is_mitigated=True)
    elif status_filter == 'false_positive':
        vulns = vulns.filter(is_false_positive=True)

    vulns = vulns.order_by('-cvss_score', '-discovered_at')

    context = {
        'vulnerabilities': vulns,
        'severity_filter': severity_filter,
        'status_filter': status_filter,
        'severity_choices': VulnerabilitySeverity.choices,
    }

    return render(request, 'adversarial/vulnerabilities_list.html', context)


@login_required
@user_passes_test(is_staff)
def vulnerability_detail(request, vuln_id):
    """View details of a specific vulnerability."""
    vuln = get_object_or_404(Vulnerability, id=vuln_id)
    mitigations = vuln.mitigations.all()
    alerts = vuln.alerts.all()

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'mark_mitigated':
            vuln.is_mitigated = True
            vuln.mitigated_at = timezone.now()
            vuln.save()
            messages.success(request, 'Vulnerability marked as mitigated.')

        elif action == 'mark_false_positive':
            vuln.is_false_positive = True
            vuln.save()
            messages.warning(request, 'Vulnerability marked as false positive.')

        elif action == 'verify':
            vuln.is_verified = True
            vuln.verified_at = timezone.now()
            vuln.save()
            messages.success(request, 'Vulnerability verified.')

        return redirect('adversarial:vulnerability_detail', vuln_id=vuln.id)

    context = {
        'vulnerability': vuln,
        'mitigations': mitigations,
        'alerts': alerts,
    }

    return render(request, 'adversarial/vulnerability_detail.html', context)


@login_required
@user_passes_test(is_staff)
def mitigations_list(request):
    """List all mitigations with filtering."""
    priority_filter = request.GET.get('priority', '')
    status_filter = request.GET.get('status', '')

    mitigations = Mitigation.objects.all()

    if priority_filter:
        mitigations = mitigations.filter(priority=priority_filter)
    if status_filter == 'pending':
        mitigations = mitigations.filter(is_implemented=False)
    elif status_filter == 'implemented':
        mitigations = mitigations.filter(is_implemented=True, is_verified=False)
    elif status_filter == 'verified':
        mitigations = mitigations.filter(is_verified=True)

    mitigations = mitigations.order_by('priority', '-created_at')

    context = {
        'mitigations': mitigations,
        'priority_filter': priority_filter,
        'status_filter': status_filter,
    }

    return render(request, 'adversarial/mitigations_list.html', context)


@login_required
@user_passes_test(is_staff)
def mitigation_detail(request, mitigation_id):
    """View details of a specific mitigation."""
    mitigation = get_object_or_404(Mitigation, id=mitigation_id)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'implement':
            mitigation.is_implemented = True
            mitigation.implemented_by = request.user
            mitigation.implemented_at = timezone.now()
            mitigation.implementation_notes = request.POST.get('notes', '')
            mitigation.save()
            messages.success(request, 'Mitigation marked as implemented.')

        elif action == 'verify':
            mitigation.is_verified = True
            mitigation.verified_by = request.user
            mitigation.verified_at = timezone.now()
            mitigation.save()

            # Also mark vulnerability as mitigated if all mitigations verified
            vuln = mitigation.vulnerability
            if vuln and not vuln.mitigations.filter(is_verified=False).exists():
                vuln.is_mitigated = True
                vuln.mitigated_at = timezone.now()
                vuln.save()

            messages.success(request, 'Mitigation verified.')

        return redirect('adversarial:mitigation_detail', mitigation_id=mitigation.id)

    context = {
        'mitigation': mitigation,
    }

    return render(request, 'adversarial/mitigation_detail.html', context)


@login_required
@user_passes_test(is_staff)
def alerts_list(request):
    """List all designer alerts."""
    level_filter = request.GET.get('level', '')
    ack_filter = request.GET.get('acknowledged', '')

    alerts = DesignerAlert.objects.all()

    if level_filter:
        alerts = alerts.filter(level=level_filter)
    if ack_filter == 'unack':
        alerts = alerts.filter(is_acknowledged=False)
    elif ack_filter == 'ack':
        alerts = alerts.filter(is_acknowledged=True)

    alerts = alerts.order_by('-created_at')

    context = {
        'alerts': alerts,
        'level_filter': level_filter,
        'ack_filter': ack_filter,
    }

    return render(request, 'adversarial/alerts_list.html', context)


@login_required
@user_passes_test(is_staff)
def alert_acknowledge(request, alert_id):
    """Acknowledge a designer alert."""
    alert = get_object_or_404(DesignerAlert, id=alert_id)

    if request.method == 'POST':
        alert.is_acknowledged = True
        alert.acknowledged_by = request.user
        alert.acknowledged_at = timezone.now()
        alert.acknowledgement_notes = request.POST.get('notes', '')
        alert.save()
        messages.success(request, 'Alert acknowledged.')

    return redirect('adversarial:alerts_list')


@login_required
@user_passes_test(is_staff)
def schedule_test(request):
    """Schedule a new adversarial test."""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        target_component = request.POST.get('target_component')
        attack_vectors = request.POST.getlist('attack_vectors')

        test = AdversarialTest.objects.create(
            name=name,
            description=description,
            target_component=target_component,
            attack_vectors=attack_vectors,
            scheduled_by=request.user,
            status=TestStatus.SCHEDULED,
        )

        messages.success(request, f'Test "{name}" scheduled successfully.')
        return redirect('adversarial:test_detail', test_id=test.id)

    # Available attack vectors
    from .models import AttackVectorCategory
    attack_vectors = AttackVectorCategory.choices

    context = {
        'attack_vectors': attack_vectors,
    }

    return render(request, 'adversarial/schedule_test.html', context)


@login_required
@user_passes_test(is_staff)
def risk_report(request):
    """
    Generate comprehensive risk report.

    HTP-DSM-NEURO-QSECBIT-NSE security posture assessment.
    """
    # Aggregate vulnerability data
    vulns = Vulnerability.objects.filter(is_mitigated=False, is_false_positive=False)

    severity_breakdown = {
        'critical': vulns.filter(severity=VulnerabilitySeverity.CRITICAL).count(),
        'high': vulns.filter(severity=VulnerabilitySeverity.HIGH).count(),
        'medium': vulns.filter(severity=VulnerabilitySeverity.MEDIUM).count(),
        'low': vulns.filter(severity=VulnerabilitySeverity.LOW).count(),
    }

    # Component breakdown
    component_vulns = vulns.values('test__target_component').annotate(
        count=Count('id'),
        avg_cvss=Avg('cvss_score')
    )

    # Attack vector breakdown
    vector_vulns = vulns.values('attack_vector').annotate(
        count=Count('id')
    )

    # Recent test trend
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_tests = AdversarialTest.objects.filter(
        completed_at__gte=thirty_days_ago
    ).order_by('completed_at')

    # Mitigation progress
    total_mitigations = Mitigation.objects.count()
    implemented = Mitigation.objects.filter(is_implemented=True).count()
    verified = Mitigation.objects.filter(is_verified=True).count()

    context = {
        'total_vulns': vulns.count(),
        'severity_breakdown': severity_breakdown,
        'component_vulns': list(component_vulns),
        'vector_vulns': list(vector_vulns),
        'recent_tests': recent_tests,
        'mitigation_progress': {
            'total': total_mitigations,
            'implemented': implemented,
            'verified': verified,
            'pending': total_mitigations - implemented,
        },
        'avg_cvss': vulns.aggregate(avg=Avg('cvss_score'))['avg'] or 0,
    }

    return render(request, 'adversarial/risk_report.html', context)


# ====================
# API Endpoints
# ====================

@login_required
@require_http_methods(["GET"])
def api_dashboard_stats(request):
    """API endpoint for dashboard statistics."""
    active_vulns = Vulnerability.objects.filter(
        is_mitigated=False, is_false_positive=False
    )

    return JsonResponse({
        'total_tests': AdversarialTest.objects.count(),
        'active_vulnerabilities': active_vulns.count(),
        'critical_vulnerabilities': active_vulns.filter(
            severity=VulnerabilitySeverity.CRITICAL
        ).count(),
        'pending_mitigations': Mitigation.objects.filter(is_implemented=False).count(),
        'unacknowledged_alerts': DesignerAlert.objects.filter(is_acknowledged=False).count(),
        'average_cvss': round(
            active_vulns.aggregate(avg=Avg('cvss_score'))['avg'] or 0, 2
        ),
    })


@login_required
@require_http_methods(["GET"])
def api_vulnerability_trend(request):
    """API endpoint for vulnerability trend data."""
    days = int(request.GET.get('days', 30))
    start_date = timezone.now() - timedelta(days=days)

    vulns = Vulnerability.objects.filter(
        discovered_at__gte=start_date
    ).extra(
        select={'day': 'date(discovered_at)'}
    ).values('day').annotate(count=Count('id')).order_by('day')

    return JsonResponse({
        'trend': list(vulns),
        'period_days': days,
    })
