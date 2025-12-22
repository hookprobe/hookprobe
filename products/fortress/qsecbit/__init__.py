"""
HookProbe Fortress QSecBit Module

Fortress-specific QSecBit agent with enhanced telemetry:
- nftables policy monitoring
- MACsec status tracking
- OpenFlow flow analysis
- Integration with monitoring stack
"""

__all__ = ['QSecBitFortressAgent', 'QSecBitConfig', 'QSecBitSample']
__version__ = '5.0.0'


def __getattr__(name):
    """Lazy import to avoid circular import when running as __main__"""
    if name in __all__:
        from . import fortress_agent
        return getattr(fortress_agent, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
