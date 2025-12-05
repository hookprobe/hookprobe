"""
SDN Views - Simple web interface for VLAN and device management.
"""

import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone

from .models import (
    DeviceCategory, VLAN, RegisteredDevice,
    GuardianConfig, NetworkScan
)


@login_required
def dashboard(request):
    """SDN dashboard - overview of VLANs and devices."""
    context = {
        'vlans': VLAN.objects.filter(owner=request.user, is_active=True),
        'devices': RegisteredDevice.objects.filter(owner=request.user)[:10],
        'categories': DeviceCategory.objects.all(),
        'guardians': GuardianConfig.objects.filter(guardian__owner=request.user),
    }
    return render(request, 'sdn/dashboard.html', context)


@login_required
def device_list(request):
    """List all registered devices."""
    devices = RegisteredDevice.objects.filter(owner=request.user)
    categories = DeviceCategory.objects.all()

    if request.method == 'POST':
        # Quick add device
        mac = request.POST.get('mac_address', '').strip().upper()
        name = request.POST.get('friendly_name', '').strip()
        category_id = request.POST.get('category')

        if mac and name:
            category = None
            if category_id:
                category = DeviceCategory.objects.filter(id=category_id).first()

            RegisteredDevice.objects.update_or_create(
                mac_address=mac,
                owner=request.user,
                defaults={
                    'friendly_name': name,
                    'category': category,
                }
            )
            messages.success(request, f'Device "{name}" registered successfully.')
            return redirect('sdn:device_list')

    context = {
        'devices': devices,
        'categories': categories,
    }
    return render(request, 'sdn/device_list.html', context)


@login_required
def device_edit(request, device_id):
    """Edit a registered device."""
    device = get_object_or_404(RegisteredDevice, id=device_id, owner=request.user)
    categories = DeviceCategory.objects.all()
    vlans = VLAN.objects.filter(owner=request.user, is_active=True)

    if request.method == 'POST':
        device.friendly_name = request.POST.get('friendly_name', device.friendly_name)
        device.hostname = request.POST.get('hostname', '')
        device.manufacturer = request.POST.get('manufacturer', '')
        device.model = request.POST.get('model', '')
        device.notes = request.POST.get('notes', '')
        device.is_active = request.POST.get('is_active') == 'on'
        device.is_blocked = request.POST.get('is_blocked') == 'on'

        category_id = request.POST.get('category')
        if category_id:
            device.category = DeviceCategory.objects.filter(id=category_id).first()
        else:
            device.category = None

        vlan_id = request.POST.get('vlan')
        if vlan_id:
            device.vlan = VLAN.objects.filter(id=vlan_id, owner=request.user).first()
        else:
            device.vlan = None

        device.save()
        messages.success(request, f'Device "{device.friendly_name}" updated.')
        return redirect('sdn:device_list')

    context = {
        'device': device,
        'categories': categories,
        'vlans': vlans,
    }
    return render(request, 'sdn/device_edit.html', context)


@login_required
def device_delete(request, device_id):
    """Delete a registered device."""
    device = get_object_or_404(RegisteredDevice, id=device_id, owner=request.user)
    if request.method == 'POST':
        name = device.friendly_name
        device.delete()
        messages.success(request, f'Device "{name}" deleted.')
    return redirect('sdn:device_list')


@login_required
def vlan_list(request):
    """List and manage VLANs."""
    vlans = VLAN.objects.filter(owner=request.user)
    categories = DeviceCategory.objects.all()

    if request.method == 'POST':
        # Create new VLAN
        vlan_id = request.POST.get('vlan_id')
        name = request.POST.get('name', '').strip()
        subnet = request.POST.get('subnet', '').strip()
        gateway = request.POST.get('gateway', '').strip()
        dhcp_start = request.POST.get('dhcp_start', '').strip()
        dhcp_end = request.POST.get('dhcp_end', '').strip()
        category_id = request.POST.get('category')

        if vlan_id and name and subnet:
            category = None
            if category_id:
                category = DeviceCategory.objects.filter(id=category_id).first()

            VLAN.objects.create(
                vlan_id=int(vlan_id),
                name=name,
                subnet=subnet,
                gateway=gateway or subnet.replace('.0/', '.1/').split('/')[0],
                dhcp_start=dhcp_start or gateway,
                dhcp_end=dhcp_end or gateway,
                category=category,
                owner=request.user,
            )
            messages.success(request, f'VLAN {vlan_id} "{name}" created.')
            return redirect('sdn:vlan_list')

    context = {
        'vlans': vlans,
        'categories': categories,
    }
    return render(request, 'sdn/vlan_list.html', context)


@login_required
def guardian_setup(request, guardian_id=None):
    """Guardian AP setup - SSID selection and bridging configuration."""
    # Get or create guardian config
    config = None
    scans = []

    if guardian_id:
        config = get_object_or_404(
            GuardianConfig,
            guardian_id=guardian_id,
            guardian__owner=request.user
        )
        scans = NetworkScan.objects.filter(guardian_id=guardian_id).order_by('-signal_strength')[:20]

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'scan' and config:
            # Trigger network scan (in real implementation, this sends command to Guardian)
            messages.info(request, 'Network scan initiated. Results will appear shortly.')
            return redirect('sdn:guardian_setup', guardian_id=guardian_id)

        elif action == 'connect' and config:
            # Connect to upstream SSID
            config.upstream_ssid = request.POST.get('upstream_ssid', '')
            config.upstream_password = request.POST.get('upstream_password', '')
            config.upstream_security = request.POST.get('upstream_security', 'wpa2')
            config.save()
            messages.success(request, f'Connecting to "{config.upstream_ssid}"...')
            return redirect('sdn:guardian_setup', guardian_id=guardian_id)

        elif action == 'hotspot' and config:
            # Update hotspot settings
            config.hotspot_ssid = request.POST.get('hotspot_ssid', config.hotspot_ssid)
            config.hotspot_password = request.POST.get('hotspot_password', config.hotspot_password)
            config.hotspot_channel = int(request.POST.get('hotspot_channel', 6))
            config.hotspot_band = request.POST.get('hotspot_band', 'dual')
            config.bridge_lan = request.POST.get('bridge_lan') == 'on'
            config.bridge_upstream = request.POST.get('bridge_upstream') == 'on'
            config.save()
            messages.success(request, 'Hotspot configuration updated.')
            return redirect('sdn:guardian_setup', guardian_id=guardian_id)

    context = {
        'config': config,
        'scans': scans,
    }
    return render(request, 'sdn/guardian_setup.html', context)


@login_required
def category_list(request):
    """Manage device categories."""
    categories = DeviceCategory.objects.all()

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        default_vlan = request.POST.get('default_vlan')
        icon = request.POST.get('icon', 'device_hub')
        color = request.POST.get('color', '#607D8B')
        allow_internet = request.POST.get('allow_internet') == 'on'
        allow_local = request.POST.get('allow_local_network') == 'on'
        isolate = request.POST.get('isolate_clients') == 'on'

        if name and default_vlan:
            DeviceCategory.objects.create(
                name=name,
                default_vlan=int(default_vlan),
                icon=icon,
                color=color,
                allow_internet=allow_internet,
                allow_local_network=allow_local,
                isolate_clients=isolate,
            )
            messages.success(request, f'Category "{name}" created.')
            return redirect('sdn:category_list')

    context = {
        'categories': categories,
    }
    return render(request, 'sdn/category_list.html', context)
