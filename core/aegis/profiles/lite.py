"""
AEGIS-Lite Profile — Guardian (1.5GB)

Lightweight AEGIS for portable devices.
Cloud-only LLM inference via OpenRouter.
3-layer memory (session + behavioral + threat_intel).
All 8 agents active with cloud fallback.
"""

LITE_PROFILE = {
    "name": "lite",
    "tier": "guardian",
    "ram_budget_mb": 120,

    # Inference: cloud-only (no local LLM)
    "inference": {
        "mode": "cloud",
        "local_model": None,
        "cloud_enabled": True,
        "max_context_tokens": 4096,
    },

    # Agents: all 8 active
    "agents": {
        "enabled": [
            "ORACLE", "WATCHDOG", "GUARDIAN", "SHIELD",
            "VIGIL", "SCOUT", "FORGE", "MEDIC",
        ],
        "disabled": [],
    },

    # Memory: 3 layers
    "memory": {
        "layers": ["session", "behavioral", "threat_intel"],
        "max_session_entries": 200,
        "max_threat_intel_entries": 2000,
        "decay_interval_hours": 12,
    },

    # Bridges: direct NAPSE + dnsXai
    "bridges": {
        "enabled": ["qsecbit", "dnsxai", "dhcp", "napse"],
        "disabled": ["wan"],
        "mesh_relay": False,
    },

    # Tools: standard set
    "tools": {
        "enabled": [
            "block_ip", "unblock_ip", "rate_limit",
            "dns_sinkhole", "get_network_status",
            "scan_device", "get_device_info",
            "check_dns_status", "get_threat_summary",
        ],
        "disabled_categories": ["advanced"],
    },

    # Autonomous: scheduler + watcher
    "autonomous": {
        "scheduler_enabled": True,
        "watcher_enabled": True,
        "psyche_enabled": False,  # Too heavy for 1.5GB
        "self_model_enabled": True,
    },

    # MSSP: full intelligence loop
    "mssp": {
        "enabled": True,
        "heartbeat_interval": 60,
        "submit_findings": True,
        "poll_recommendations": True,
        "poll_interval": 15,
    },
}
