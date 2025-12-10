#!/usr/bin/env python3
"""
Demo Data Generator for HookProbe Globe Visualization

Phase 1C: Expanded Demo Data (+30%)

Generates realistic-looking threat events for testing and demos.
Now with more nodes, threat sources, attack types, and event variety.
"""

import random
from datetime import datetime
from typing import Dict, Any, List

# ============================================================================
# HOOKPROBE NODES (~30% more nodes than before)
# ============================================================================

HOOKPROBE_NODES: List[Dict[str, Any]] = [
    # North America - Guardians
    {"id": "guardian-sf-001", "tier": "guardian", "lat": 37.7749, "lng": -122.4194, "label": "SF Guardian"},
    {"id": "guardian-nyc-001", "tier": "guardian", "lat": 40.7128, "lng": -74.0060, "label": "NYC Guardian"},
    {"id": "guardian-la-001", "tier": "guardian", "lat": 34.0522, "lng": -118.2437, "label": "LA Guardian"},
    {"id": "guardian-miami-001", "tier": "guardian", "lat": 25.7617, "lng": -80.1918, "label": "Miami Guardian"},

    # Europe - Fortresses
    {"id": "fortress-lon-001", "tier": "fortress", "lat": 51.5074, "lng": -0.1278, "label": "London Fortress"},
    {"id": "fortress-ams-001", "tier": "fortress", "lat": 52.3676, "lng": 4.9041, "label": "Amsterdam Fortress"},
    {"id": "fortress-par-001", "tier": "fortress", "lat": 48.8566, "lng": 2.3522, "label": "Paris Fortress"},

    # Asia Pacific - Fortresses & Guardians
    {"id": "fortress-tok-001", "tier": "fortress", "lat": 35.6762, "lng": 139.6503, "label": "Tokyo Fortress"},
    {"id": "fortress-hk-001", "tier": "fortress", "lat": 22.3193, "lng": 114.1694, "label": "Hong Kong Fortress"},
    {"id": "guardian-syd-001", "tier": "guardian", "lat": -33.8688, "lng": 151.2093, "label": "Sydney Guardian"},

    # Sentinels - IoT Validators (edge devices)
    {"id": "sentinel-ber-001", "tier": "sentinel", "lat": 52.5200, "lng": 13.4050, "label": "Berlin Sentinel"},
    {"id": "sentinel-sgp-001", "tier": "sentinel", "lat": 1.3521, "lng": 103.8198, "label": "Singapore Sentinel"},
    {"id": "sentinel-dub-001", "tier": "sentinel", "lat": 53.3498, "lng": -6.2603, "label": "Dublin Sentinel"},
    {"id": "sentinel-tor-001", "tier": "sentinel", "lat": 43.6532, "lng": -79.3832, "label": "Toronto Sentinel"},
    {"id": "sentinel-mel-001", "tier": "sentinel", "lat": -37.8136, "lng": 144.9631, "label": "Melbourne Sentinel"},
    {"id": "sentinel-sto-001", "tier": "sentinel", "lat": 59.3293, "lng": 18.0686, "label": "Stockholm Sentinel"},

    # Nexus - ML/AI Compute nodes
    {"id": "nexus-fra-001", "tier": "nexus", "lat": 50.1109, "lng": 8.6821, "label": "Frankfurt Nexus"},
    {"id": "nexus-ash-001", "tier": "nexus", "lat": 39.0438, "lng": -77.4874, "label": "Ashburn Nexus"},
    {"id": "nexus-sin-001", "tier": "nexus", "lat": 1.2897, "lng": 103.8501, "label": "Singapore Nexus"},
]

# ============================================================================
# THREAT SOURCES (~30% more locations)
# ============================================================================

THREAT_SOURCES: List[Dict[str, Any]] = [
    # China
    {"lat": 39.9042, "lng": 116.4074, "label": "Beijing"},
    {"lat": 31.2304, "lng": 121.4737, "label": "Shanghai"},
    {"lat": 22.5431, "lng": 114.0579, "label": "Shenzhen"},
    {"lat": 23.1291, "lng": 113.2644, "label": "Guangzhou"},

    # Russia
    {"lat": 55.7558, "lng": 37.6173, "label": "Moscow"},
    {"lat": 59.9343, "lng": 30.3351, "label": "St. Petersburg"},
    {"lat": 56.8389, "lng": 60.6057, "label": "Yekaterinburg"},

    # Iran
    {"lat": 35.6892, "lng": 51.3890, "label": "Tehran"},

    # North Korea
    {"lat": 39.0392, "lng": 125.7625, "label": "Pyongyang"},

    # Southeast Asia
    {"lat": 37.5665, "lng": 126.9780, "label": "Seoul"},
    {"lat": 25.0330, "lng": 121.5654, "label": "Taipei"},
    {"lat": 14.5995, "lng": 120.9842, "label": "Manila"},
    {"lat": 10.8231, "lng": 106.6297, "label": "Ho Chi Minh City"},

    # South Asia
    {"lat": 19.0760, "lng": 72.8777, "label": "Mumbai"},
    {"lat": 28.6139, "lng": 77.2090, "label": "New Delhi"},
    {"lat": 24.8607, "lng": 67.0011, "label": "Karachi"},

    # South America
    {"lat": -23.5505, "lng": -46.6333, "label": "São Paulo"},
    {"lat": -34.6037, "lng": -58.3816, "label": "Buenos Aires"},

    # Africa
    {"lat": 6.5244, "lng": 3.3792, "label": "Lagos"},
    {"lat": -26.2041, "lng": 28.0473, "label": "Johannesburg"},
    {"lat": 30.0444, "lng": 31.2357, "label": "Cairo"},

    # Eastern Europe
    {"lat": 50.4501, "lng": 30.5234, "label": "Kyiv"},
    {"lat": 44.4268, "lng": 26.1025, "label": "Bucharest"},
]

# ============================================================================
# ATTACK TYPES (~30% more types with improved metadata)
# ============================================================================

ATTACK_TYPES = [
    # DDoS variants
    ("ddos_volumetric", 0.75, "Volumetric DDoS flood"),
    ("ddos_amplification", 0.80, "DNS/NTP amplification attack"),
    ("ddos_slowloris", 0.55, "Slowloris connection exhaustion"),

    # Scanning & Reconnaissance
    ("port_scan", 0.30, "Port scanning reconnaissance"),
    ("vuln_scan", 0.40, "Vulnerability scanner detected"),
    ("service_enum", 0.35, "Service enumeration attempt"),

    # Brute Force
    ("brute_force_ssh", 0.50, "SSH brute force attack"),
    ("brute_force_rdp", 0.55, "RDP brute force attack"),
    ("credential_stuffing", 0.60, "Credential stuffing attack"),

    # Malware & C2
    ("malware_c2", 0.90, "Malware C2 communication"),
    ("ransomware_beacon", 0.95, "Ransomware beacon detected"),
    ("botnet_activity", 0.85, "Botnet activity detected"),

    # Web Application Attacks
    ("sql_injection", 0.65, "SQL injection attempt"),
    ("xss_attempt", 0.45, "Cross-site scripting attempt"),
    ("rfi_lfi", 0.70, "Remote/Local file inclusion"),
    ("path_traversal", 0.55, "Path traversal attempt"),
    ("csrf_attack", 0.40, "Cross-site request forgery"),

    # API Attacks
    ("api_abuse", 0.50, "API rate limit abuse"),
    ("broken_auth", 0.65, "Authentication bypass attempt"),

    # Zero-Day Indicators
    ("zero_day_indicator", 0.95, "Potential zero-day exploit"),
    ("unknown_exploit", 0.80, "Unknown exploitation pattern"),
]

# ============================================================================
# MITIGATION METHODS
# ============================================================================

MITIGATION_METHODS = [
    "xdp_drop",           # XDP/eBPF kernel-level drop
    "rate_limit",         # Rate limiting
    "geo_block",          # Geographic blocking
    "signature_match",    # IDS/IPS signature match
    "ml_detection",       # ML model detection
    "anomaly_block",      # Anomaly-based blocking
    "reputation_block",   # IP reputation blocking
    "behavior_block",     # Behavioral analysis block
    "captcha_challenge",  # CAPTCHA challenge
    "honeypot_redirect",  # Honeypot redirection
]

# ============================================================================
# DEMO DATA GENERATOR
# ============================================================================


class DemoDataGenerator:
    """Generates demo events for globe visualization testing."""

    def __init__(self):
        self.event_counter = 0
        self.nodes = HOOKPROBE_NODES.copy()

        # Track recent events for more realistic patterns
        self._recent_attacks: List[str] = []  # Recent attack types
        self._active_campaigns: Dict[str, int] = {}  # Source -> attack count

    def generate_event(self) -> Dict[str, Any]:
        """Generate a random event."""
        self.event_counter += 1

        # Weighted event distribution:
        # 55% attacks, 25% repelled, 15% node status, 5% qsecbit updates
        roll = random.random()

        if roll < 0.55:
            return self._generate_attack()
        elif roll < 0.80:
            return self._generate_repelled()
        elif roll < 0.95:
            return self._generate_node_status()
        else:
            return self._generate_qsecbit_update()

    def _generate_attack(self) -> Dict[str, Any]:
        """Generate an attack_detected event."""
        source = random.choice(THREAT_SOURCES)
        target = random.choice(self.nodes)
        attack_name, base_severity, description = random.choice(ATTACK_TYPES)

        # Add some campaign persistence (30% chance to continue existing campaign)
        if self._active_campaigns and random.random() < 0.3:
            # Continue an existing attack campaign
            campaign_source = random.choice(list(self._active_campaigns.keys()))
            for s in THREAT_SOURCES:
                if s["label"] == campaign_source:
                    source = s
                    break
            self._active_campaigns[campaign_source] = self._active_campaigns.get(campaign_source, 0) + 1
        else:
            # Start new campaign
            self._active_campaigns[source["label"]] = 1

        # Vary severity slightly
        severity = max(0.1, min(1.0, base_severity + random.uniform(-0.15, 0.15)))

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
            "attack_type": attack_name,
            "severity": round(severity, 3),
            "description": description,
            "campaign_count": self._active_campaigns.get(source["label"], 1),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _generate_repelled(self) -> Dict[str, Any]:
        """Generate an attack_repelled event."""
        source = random.choice(THREAT_SOURCES)
        target = random.choice(self.nodes)
        attack_name, base_severity, description = random.choice(ATTACK_TYPES)
        mitigation = random.choice(MITIGATION_METHODS)

        # Response time varies by mitigation type
        if mitigation in ["xdp_drop", "geo_block"]:
            response_ms = random.randint(1, 10)  # Very fast
        elif mitigation in ["signature_match", "reputation_block"]:
            response_ms = random.randint(5, 30)  # Fast
        else:
            response_ms = random.randint(20, 100)  # Normal

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
            "attack_type": attack_name,
            "description": description,
            "mitigation": mitigation,
            "response_ms": response_ms,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _generate_node_status(self) -> Dict[str, Any]:
        """Generate node status update with realistic Qsecbit distribution."""
        nodes_status = []
        for node in self.nodes:
            # More realistic Qsecbit distribution:
            # 70% GREEN, 20% AMBER, 10% RED
            roll = random.random()
            if roll < 0.70:
                qsecbit = random.uniform(0.1, 0.44)  # GREEN
            elif roll < 0.90:
                qsecbit = random.uniform(0.45, 0.69)  # AMBER
            else:
                qsecbit = random.uniform(0.70, 0.95)  # RED

            status = "green" if qsecbit < 0.45 else ("amber" if qsecbit < 0.70 else "red")

            nodes_status.append({
                "id": node["id"],
                "tier": node["tier"],
                "lat": node["lat"],
                "lng": node["lng"],
                "label": node["label"],
                "qsecbit": round(qsecbit, 3),
                "status": status,
                "online": True,  # All demo nodes are online
            })

        return {
            "type": "node_status",
            "nodes": nodes_status,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _generate_qsecbit_update(self) -> Dict[str, Any]:
        """Generate a Qsecbit score update for a single node."""
        node = random.choice(self.nodes)

        # Generate Qsecbit components
        drift = random.uniform(0.0, 0.4)
        attack_probability = random.uniform(0.0, 0.5)
        classifier_decay = random.uniform(0.0, 0.3)
        quantum_drift = random.uniform(0.0, 0.3)

        # Calculate weighted score
        score = 0.30 * drift + 0.30 * attack_probability + 0.20 * classifier_decay + 0.20 * quantum_drift
        score = min(1.0, max(0.0, score))

        if score < 0.45:
            rag_status = "GREEN"
        elif score < 0.70:
            rag_status = "AMBER"
        else:
            rag_status = "RED"

        return {
            "type": "qsecbit_update",
            "node_id": node["id"],
            "score": round(score, 4),
            "components": {
                "drift": round(drift, 4),
                "attack_probability": round(attack_probability, 4),
                "classifier_decay": round(classifier_decay, 4),
                "quantum_drift": round(quantum_drift, 4),
            },
            "rag_status": rag_status,
            "timestamp": datetime.utcnow().isoformat()
        }

    def generate_burst(self, count: int = 5) -> List[Dict[str, Any]]:
        """Generate a burst of events (simulating an attack wave)."""
        events = []
        # Pick a single source for coordinated attack
        source = random.choice(THREAT_SOURCES)

        for _ in range(count):
            target = random.choice(self.nodes)
            attack_name, base_severity, description = random.choice(ATTACK_TYPES[:6])  # DDoS types

            events.append({
                "type": "attack_detected",
                "id": f"burst-{self.event_counter}",
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
                "attack_type": attack_name,
                "severity": min(1.0, base_severity + random.uniform(0, 0.1)),
                "description": description,
                "burst": True,
                "timestamp": datetime.utcnow().isoformat()
            })
            self.event_counter += 1

        return events

    def get_full_snapshot(self) -> Dict[str, Any]:
        """Get a complete snapshot of all nodes for initial page load."""
        return self._generate_node_status()

    def get_statistics(self) -> Dict[str, Any]:
        """Get demo statistics."""
        return {
            "total_nodes": len(self.nodes),
            "nodes_by_tier": {
                "sentinel": len([n for n in self.nodes if n["tier"] == "sentinel"]),
                "guardian": len([n for n in self.nodes if n["tier"] == "guardian"]),
                "fortress": len([n for n in self.nodes if n["tier"] == "fortress"]),
                "nexus": len([n for n in self.nodes if n["tier"] == "nexus"]),
            },
            "threat_sources": len(THREAT_SOURCES),
            "attack_types": len(ATTACK_TYPES),
            "events_generated": self.event_counter,
            "active_campaigns": len(self._active_campaigns),
        }


if __name__ == "__main__":
    # Test the generator
    gen = DemoDataGenerator()
    import json

    print("=== Demo Data Generator Test ===\n")
    print(f"Statistics: {json.dumps(gen.get_statistics(), indent=2)}\n")

    print("=== Sample Events ===\n")
    for i in range(10):
        event = gen.generate_event()
        print(f"Event {i+1}: {event['type']}")
        print(json.dumps(event, indent=2))
        print()
