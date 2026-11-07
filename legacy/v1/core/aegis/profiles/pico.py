"""
AEGIS-Pico Profile — Sentinel (256MB)

Minimal AEGIS for ultra-constrained devices.
No LLM inference — template-only ORACLE responses.
2-layer memory (session + threat_intel).
3 active agents (ORACLE, WATCHDOG, GUARDIAN).
"""

PICO_PROFILE = {
    "name": "pico",
    "tier": "sentinel",
    "ram_budget_mb": 25,

    # Inference: no LLM, template responses only
    "inference": {
        "mode": "template",  # No LLM calls at all
        "local_model": None,
        "cloud_enabled": False,
        "max_context_tokens": 0,
    },

    # Agents: minimal subset
    "agents": {
        "enabled": ["ORACLE", "WATCHDOG", "GUARDIAN"],
        "disabled": ["SHIELD", "VIGIL", "SCOUT", "FORGE", "MEDIC"],
    },

    # Memory: 2 layers only
    "memory": {
        "layers": ["session", "threat_intel"],
        "max_session_entries": 50,
        "max_threat_intel_entries": 500,
        "decay_interval_hours": 24,
    },

    # Bridges: mesh relay only (no local NAPSE)
    "bridges": {
        "enabled": ["dhcp"],
        "disabled": ["qsecbit", "dnsxai", "wan", "napse"],
        "mesh_relay": True,  # Receive pre-processed alerts via mesh gossip
    },

    # Neuro-Kernel: receive-only (deploy pre-built eBPF from Nexus)
    "neurokernel": {
        "enabled": False,
        "inference_mode": "none",
        "streaming_rag": False,
        "shadow_pentester": False,
        "llm_monitor": False,
    },

    # Tools: defense-only subset
    "tools": {
        "enabled": [
            "block_ip", "unblock_ip", "rate_limit",
            "dns_sinkhole", "get_network_status",
        ],
        "disabled_categories": [
            "scanning", "configuration", "advanced",
        ],
    },

    # Autonomous: minimal
    "autonomous": {
        "scheduler_enabled": False,
        "watcher_enabled": True,  # React to mesh-relayed signals
        "psyche_enabled": False,
        "self_model_enabled": False,
    },

    # MSSP: report findings, receive recommendations
    "mssp": {
        "enabled": True,
        "heartbeat_interval": 120,  # 2 min (save bandwidth)
        "submit_findings": True,
        "poll_recommendations": True,
        "poll_interval": 30,  # 30s recommendation poll
    },
}
