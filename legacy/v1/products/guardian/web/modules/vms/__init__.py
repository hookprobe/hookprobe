"""
VMs Module - Virtual Machine Management for Guardian
Supports Home Assistant and OpenMediaVault VMs via libvirt/QEMU-KVM
"""
from flask import Blueprint

vms_bp = Blueprint('vms', __name__, template_folder='../../templates')

from . import views  # noqa: E402, F401
