#!/usr/bin/env python3
"""
Demo Data Generator for HookProbe Globe Visualization

Generates realistic-looking threat events for testing and demos.
"""

import random
from datetime import datetime
from typing import Dict, Any, List

# Sample locations representing HookProbe nodes and threat sources
HOOKPROBE_NODES: List[Dict[str, Any]] = [
    {"id": "guardian-sf-001", "tier": "guardian", "lat": 37.7749, "lng": -122.4194, "label": "SF Guardian"},
    {"id": "guardian-nyc-001", "tier": "guardian", "lat": 40.7128, "lng": -74.0060, "label": "NYC Guardian"},
    {"id": "fortress-lon-001", "tier": "fortress", "lat": 51.5074, "lng": -0.1278, "label": "London Fortress"},
    {"id": "fortress-tok-001", "tier": "fortress", "lat": 35.6762, "lng": 139.6503, "label": "Tokyo Fortress"},
    {"id": "sentinel-syd-001", "tier": "sentinel", "lat": -33.8688, "lng": 151.2093, "label": "Sydney Sentinel"},
    {"id": "sentinel-ber-001", "tier": "sentinel", "lat": 52.5200, "lng": 13.4050, "label": "Berlin Sentinel"},
    {"id": "nexus-fra-001", "tier": "nexus", "lat": 50.1109, "lng": 8.6821, "label": "Frankfurt Nexus"},
    {"id": "sentinel-sgp-001", "tier": "sentinel", "lat": 1.3521, "lng": 103.8198, "label": "Singapore Sentinel"},
]

# Common attack source locations (for demo purposes)
THREAT_SOURCES: List[Dict[str, Any]] = [
    {"lat": 39.9042, "lng": 116.4074, "label": "Beijing"},
    {"lat": 55.7558, "lng": 37.6173, "label": "Moscow"},
    {"lat": 31.2304, "lng": 121.4737, "label": "Shanghai"},
    {"lat": 37.5665, "lng": 126.9780, "label": "Seoul"},
    {"lat": 25.0330, "lng": 121.5654, "label": "Taipei"},
    {"lat": 19.0760, "lng": 72.8777, "label": "Mumbai"},
    {"lat": -23.5505, "lng": -46.6333, "label": "São Paulo"},
    {"lat": 6.5244, "lng": 3.3792, "label": "Lagos"},
]

# Attack types with severity weights
ATTACK_TYPES = [
    ("ddos", 0.7),
    ("port_scan", 0.3),
    ("brute_force", 0.5),
    ("malware_c2", 0.9),
    ("sql_injection", 0.6),
    ("xss_attempt", 0.4),
]


class DemoDataGenerator:
    """Generates demo events for globe visualization testing."""

    def __init__(self):
        self.event_counter = 0
        self.nodes = HOOKPROBE_NODES.copy()

    def generate_event(self) -> Dict[str, Any]:
        """Generate a random event."""
        self.event_counter += 1

        # 60% attacks, 30% repelled, 10% node status
        roll = random.random()

        if roll < 0.60:
            return self._generate_attack()
        elif roll < 0.90:
            return self._generate_repelled()
        else:
            return self._generate_node_status()

    def _generate_attack(self) -> Dict[str, Any]:
        """Generate an attack_detected event."""
        source = random.choice(THREAT_SOURCES)
        target = random.choice(self.nodes)
        attack_type, base_severity = random.choice(ATTACK_TYPES)

        return {
            "type": "attack_detected",
            "id": f"atk-{self.event_counter}",
            "source": {
                "lat": source["lat"],
                "lng": source["lng"],
                "label": source["label"]
            },
            "target": {
                "lat": target["lat"],
                "lng": target["lng"],
                "label": target["label"],
                "node_id": target["id"]
            },
            "attack_type": attack_type,
            "severity": min(1.0, base_severity + random.uniform(-0.2, 0.2)),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _generate_repelled(self) -> Dict[str, Any]:
        """Generate an attack_repelled event."""
        source = random.choice(THREAT_SOURCES)
        target = random.choice(self.nodes)
        attack_type, _ = random.choice(ATTACK_TYPES)

        return {
            "type": "attack_repelled",
            "id": f"rep-{self.event_counter}",
            "source": {
                "lat": source["lat"],
                "lng": source["lng"],
                "label": source["label"]
            },
            "target": {
                "lat": target["lat"],
                "lng": target["lng"],
                "label": target["label"],
                "node_id": target["id"]
            },
            "attack_type": attack_type,
            "mitigation": random.choice(["xdp_drop", "rate_limit", "geo_block", "signature_match"]),
            "response_ms": random.randint(1, 50),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _generate_node_status(self) -> Dict[str, Any]:
        """Generate node status update."""
        nodes_status = []
        for node in self.nodes:
            qsecbit = random.uniform(0.1, 0.9)
            if qsecbit < 0.45:
                status = "green"
            elif qsecbit < 0.70:
                status = "amber"
            else:
                status = "red"

            nodes_status.append({
                "id": node["id"],
                "tier": node["tier"],
                "lat": node["lat"],
                "lng": node["lng"],
                "label": node["label"],
                "qsecbit": round(qsecbit, 3),
                "status": status
            })

        return {
            "type": "node_status",
            "nodes": nodes_status,
            "timestamp": datetime.utcnow().isoformat()
        }


if __name__ == "__main__":
    # Test the generator
    gen = DemoDataGenerator()
    for _ in range(5):
        import json
        print(json.dumps(gen.generate_event(), indent=2))
