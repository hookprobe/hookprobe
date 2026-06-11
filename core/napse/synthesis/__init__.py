"""
NAPSE Event Synthesis Layer — `EventType` / event-bus primitives.

NOTE (2026-06-11): the NAPSE-synthesis orchestrator (`napse/main.py`) and its
writers (clickhouse_shipper, metrics, aegis_bridge, bubble_feed, qsecbit_feed,
healing_bridge, healing_engine, notice_emitter) were removed — they never ran in
production (no container entrypoint; the destination napse_alerts/conn/dns/http/
ssl tables held 0 rows). Only `event_bus.py` remains, because its `EventType`
enum is still imported by the live `core/qsecbit/detectors/` tree and other
consumers.

Modules:
    event_bus - typed event distribution + EventType (the surviving primitive)
"""
