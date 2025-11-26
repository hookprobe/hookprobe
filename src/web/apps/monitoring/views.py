"""
Monitoring Views
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required
def monitoring_overview(request):
    """Monitoring overview with Grafana embeds"""
    context = {
        'grafana_url': 'http://10.200.5.12:3000',
    }
    return render(request, 'admin/monitoring/overview.html', context)
