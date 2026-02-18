"""
AEGIS-Full Profile — Fortress (4GB)

Full AEGIS with hybrid inference (local Ollama + cloud OpenRouter).
5-layer memory. All 8 agents. All bridges. Full autonomy.
This is the default profile.
"""

FULL_PROFILE = {
    "name": "full",
    "tier": "fortress",
    "ram_budget_mb": 512,

    # Inference: hybrid (auto switches local/cloud)
    "inference": {
        "mode": "auto",
        "local_model": "llama3.2:3b",
        "cloud_enabled": True,
        "max_context_tokens": 8192,
    },

    # Agents: all 8 active
    "agents": {
        "enabled": [
            "ORACLE", "WATCHDOG", "GUARDIAN", "SHIELD",
            "VIGIL", "SCOUT", "FORGE", "MEDIC",
        ],
        "disabled": [],
    },

    # Memory: full 5 layers
    "memory": {
        "layers": [
            "session", "behavioral", "institutional",
            "threat_intel", "decisions",
        ],
        "max_session_entries": 500,
        "max_threat_intel_entries": 10000,
        "decay_interval_hours": 6,
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

    # Autonomous: everything enabled
    "autonomous": {
        "scheduler_enabled": True,
        "watcher_enabled": True,
        "psyche_enabled": True,
        "self_model_enabled": True,
    },

    # MSSP: full intelligence loop
    "mssp": {
        "enabled": True,
        "heartbeat_interval": 60,
        "submit_findings": True,
        "poll_recommendations": True,
        "poll_interval": 10,
    },
}
