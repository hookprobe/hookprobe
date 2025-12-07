"""
Device Management Views
"""

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.generic import ListView, DetailView
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import Device, Customer, DeviceLog, DeviceMetric


@login_required
def device_list(request):
    """List all devices"""
    devices = Device.objects.select_related('customer').all()
    customers = Customer.objects.filter(is_active=True)

    context = {
        'devices': devices,
        'customers': customers,
    }
    return render(request, 'admin/devices/list.html', context)


@login_required
def device_detail(request, device_id):
    """Device detail view"""
    device = get_object_or_404(Device, device_id=device_id)
    recent_logs = device.logs.all()[:50]
    recent_metrics = device.metrics.all()[:100]

    context = {
        'device': device,
        'recent_logs': recent_logs,
        'recent_metrics': recent_metrics,
    }
    return render(request, 'admin/devices/detail.html', context)


class CustomerListView(LoginRequiredMixin, ListView):
    """List all customers"""
    model = Customer
    template_name = 'admin/customers/list.html'
    context_object_name = 'customers'
    paginate_by = 20


class CustomerDetailView(LoginRequiredMixin, DetailView):
    """Customer detail view"""
    model = Customer
    template_name = 'admin/customers/detail.html'
    context_object_name = 'customer'
    slug_field = 'tenant_id'
    slug_url_kwarg = 'tenant_id'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['devices'] = self.object.devices.all()
        return context
