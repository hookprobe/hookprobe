"""
NAPSE Event Synthesis Layer (Layer 2)

Routes structured events from the capture engine (Mojo Brain,
Python Inspector, or eBPF) to all HookProbe consumers: QSecBit,
AEGIS, D2D Bubbles, ClickHouse, Cortex, and mesh propagation.

Modules:
    event_bus       - Central typed event distribution
    qsecbit_feed    - Direct QSecBit ThreatEvent injection
    aegis_bridge    - AEGIS StandardSignal emission
    bubble_feed     - D2D bubble mDNS + connection feed
    notice_emitter  - Notice event generation
    clickhouse_shipper - Direct ClickHouse insertion
    metrics         - Prometheus metrics endpoint
"""
