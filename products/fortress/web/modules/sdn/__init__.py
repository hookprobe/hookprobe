"""
Fortress SDN Module - Unified Software-Defined Network Management

Combines device management, network policies, and OUI classification
into a single dashboard for complete network visibility and control.

Features:
- Unified device grid with IP, MAC, vendor, policy, status
- OUI-based automatic device classification
- Network policy management (VLAN or nftables filter mode)
- Real-time status updates
- Device disconnect/block/unblock controls
- Bulk operations
- Export capabilities
"""

from flask import Blueprint

sdn_bp = Blueprint('sdn', __name__)
