"""
Security & Qsecbit Views
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from .models import SecurityEvent, QsecbitScore, KaliResponse


@login_required
def security_events(request):
    """Security events view"""
    events = SecurityEvent.objects.all()[:100]
    critical_events = SecurityEvent.objects.filter(
        severity='critical',
        is_resolved=False
    )

    context = {
        'events': events,
        'critical_events': critical_events,
    }
    return render(request, 'admin/security/events.html', context)


@login_required
def qsecbit_dashboard(request):
    """Qsecbit dashboard view"""
    latest_score = QsecbitScore.objects.first()

    # Get scores for last 24 hours
    yesterday = timezone.now() - timedelta(hours=24)
    recent_scores = QsecbitScore.objects.filter(
        timestamp__gte=yesterday
    ).order_by('timestamp')

    # Get recent Kali responses
    recent_responses = KaliResponse.objects.all()[:10]

    context = {
        'latest_score': latest_score,
        'recent_scores': recent_scores,
        'recent_responses': recent_responses,
    }
    return render(request, 'admin/security/qsecbit.html', context)
