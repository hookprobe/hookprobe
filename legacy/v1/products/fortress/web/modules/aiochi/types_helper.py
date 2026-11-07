"""
AIOCHI Types Helper
Maps bubble types to network policies for the API.
"""

# Bubble type to network policy mapping
BUBBLE_TYPE_POLICIES = {
    'FAMILY': {
        'internet': True,
        'lan': True,
        'd2d': True,
        'vlan': 110,
        'description': 'Full access for family members'
    },
    'GUEST': {
        'internet': True,
        'lan': False,
        'd2d': False,
        'vlan': 150,
        'description': 'Internet only for guests'
    },
    'IOT': {
        'internet': True,
        'lan': False,
        'd2d': True,
        'vlan': 130,
        'description': 'IoT devices with D2D access'
    },
    'WORK': {
        'internet': True,
        'lan': False,
        'd2d': False,
        'vlan': 120,
        'description': 'Work devices - Internet only (laptops, phones)'
    },
    'CUSTOM': {
        'internet': True,
        'lan': False,
        'd2d': False,
        'vlan': 100,
        'description': 'Custom policy'
    },
    'family': {
        'internet': True,
        'lan': True,
        'd2d': True,
        'vlan': 110,
        'description': 'Full access for family members'
    },
    'guest': {
        'internet': True,
        'lan': False,
        'd2d': False,
        'vlan': 150,
        'description': 'Internet only for guests'
    },
    'iot': {
        'internet': True,
        'lan': False,
        'd2d': True,
        'vlan': 130,
        'description': 'IoT devices with D2D access'
    },
    'smart_home': {
        'internet': True,
        'lan': False,
        'd2d': True,
        'vlan': 130,
        'description': 'Smart home devices'
    },
    'corporate': {
        'internet': True,
        'lan': False,
        'd2d': False,
        'vlan': 120,
        'description': 'Corporate devices - Internet only'
    },
    'custom': {
        'internet': True,
        'lan': False,
        'd2d': False,
        'vlan': 100,
        'description': 'Custom policy'
    },
}


def get_bubble_type_policy(bubble_type: str) -> dict:
    """Get network policy for a bubble type."""
    return BUBBLE_TYPE_POLICIES.get(
        bubble_type,
        BUBBLE_TYPE_POLICIES.get(bubble_type.upper(), BUBBLE_TYPE_POLICIES['custom'])
    )


def get_all_bubble_types() -> list:
    """Get all available bubble types for UI."""
    return [
        {'value': 'FAMILY', 'label': 'Family', 'icon': 'fa-users', 'color': '#4fc3f7'},
        {'value': 'GUEST', 'label': 'Guest', 'icon': 'fa-user-friends', 'color': '#607D8B'},
        {'value': 'IOT', 'label': 'IoT / Smart Home', 'icon': 'fa-home', 'color': '#4CAF50'},
        {'value': 'WORK', 'label': 'Work', 'icon': 'fa-briefcase', 'color': '#9C27B0'},
        {'value': 'CUSTOM', 'label': 'Custom', 'icon': 'fa-layer-group', 'color': '#FF9800'},
    ]
