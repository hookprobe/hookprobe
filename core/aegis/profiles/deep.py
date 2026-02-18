"""
AEGIS-Deep Profile — Nexus (16GB+)

Maximum AEGIS with GPU-accelerated local LLM.
Large context window for deep analysis. 5-layer memory
with ClickHouse backing. Enhanced SCOUT with federated threat intel.
MEDIC with meta-regressive learning from red/purple teaming.
"""

DEEP_PROFILE = {
    "name": "deep",
    "tier": "nexus",
    "ram_budget_mb": 4096,

    # Inference: GPU-local preferred, cloud fallback
    "inference": {
        "mode": "auto",
        "local_model": "llama3.1:8b",
        "cloud_enabled": True,
        "max_context_tokens": 32768,
        "gpu_acceleration": True,
    },

    # Agents: all 8 with enhanced configs
    "agents": {
        "enabled": [
            "ORACLE", "WATCHDOG", "GUARDIAN", "SHIELD",
            "VIGIL", "SCOUT", "FORGE", "MEDIC",
        ],
        "disabled": [],
        "enhancements": {
            "SCOUT": {"federated_threat_intel": True},
            "MEDIC": {"meta_regressive_learning": True},
            "ORACLE": {"large_context": True},
        },
    },

    # Memory: full 5 layers with extended retention
    "memory": {
        "layers": [
            "session", "behavioral", "institutional",
            "threat_intel", "decisions",
        ],
        "max_session_entries": 2000,
        "max_threat_intel_entries": 100000,
        "decay_interval_hours": 1,
        "clickhouse_backing": True,
    },

    # Bridges: all active
    "bridges": {
        "enabled": ["qsecbit", "dnsxai", "dhcp", "wan", "napse"],
        "disabled": [],
        "mesh_relay": False,
    },

    # Tools: full set
    "tools": {
        "enabled": "all",
        "disabled_categories": [],
    },

    # Autonomous: everything enabled with enhanced cycles
    "autonomous": {
        "scheduler_enabled": True,
        "watcher_enabled": True,
        "psyche_enabled": True,
        "self_model_enabled": True,
        "dream_cycle_enabled": True,
        "reflection_interval_minutes": 15,
    },

    # MSSP: intelligence service provider (pulls analysis jobs)
    "mssp": {
        "enabled": True,
        "heartbeat_interval": 30,
        "submit_findings": True,
        "poll_recommendations": True,
        "poll_interval": 5,
        "nexus_worker": True,  # Pull analysis jobs from MSSP queue
        "nexus_worker_interval": 5,
    },
}
