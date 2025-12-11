#!/usr/bin/env python3
"""
Demo Data Generator for HookProbe Cortex Visualization

Phase 3: Enterprise Fleet Demo Data

Generates realistic enterprise-scale threat events to demonstrate:
- Value of collective defense (many endpoints = better protection)
- Multi-tenant fleet management
- Geographic distribution
- Attack patterns across organizations

Now with 75+ nodes, 30+ threat sources, 25+ attack types, and multi-organization support.
"""

import random
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import math

# ============================================================================
# DEMO ORGANIZATIONS (Multi-tenant showcase)
# ============================================================================

DEMO_ORGANIZATIONS = [
    {
        "id": "acme-corp",
        "name": "ACME Corporation",
        "industry": "Technology",
        "tier": "enterprise",
        "regions": ["North America", "Europe"],
    },
    {
        "id": "globex-inc",
        "name": "Globex Industries",
        "industry": "Manufacturing",
        "tier": "professional",
        "regions": ["North America", "Asia Pacific"],
    },
    {
        "id": "initech-systems",
        "name": "Initech Systems",
        "industry": "Financial Services",
        "tier": "enterprise",
        "regions": ["Europe", "North America"],
    },
    {
        "id": "wayne-enterprises",
        "name": "Wayne Enterprises",
        "industry": "Conglomerate",
        "tier": "enterprise",
        "regions": ["Global"],
    },
    {
        "id": "stark-industries",
        "name": "Stark Industries",
        "industry": "Defense/Technology",
        "tier": "enterprise",
        "regions": ["North America", "Europe", "Asia Pacific"],
    },
]

# ============================================================================
# HOOKPROBE NODES - Enterprise Scale (75+ nodes)
# ============================================================================

HOOKPROBE_NODES: List[Dict[str, Any]] = [
    # ==========================================================================
    # ACME CORPORATION (15 nodes)
    # ==========================================================================
    # North America - HQ
    {"id": "acme-guardian-sf-001", "tier": "guardian", "lat": 37.7749, "lng": -122.4194,
     "label": "ACME SF HQ", "customer_id": "acme-corp", "department": "Engineering"},
    {"id": "acme-guardian-sf-002", "tier": "guardian", "lat": 37.7849, "lng": -122.4094,
     "label": "ACME SF Office 2", "customer_id": "acme-corp", "department": "Engineering"},
    {"id": "acme-guardian-nyc-001", "tier": "guardian", "lat": 40.7128, "lng": -74.0060,
     "label": "ACME NYC Office", "customer_id": "acme-corp", "department": "Sales"},
    {"id": "acme-fortress-ash-001", "tier": "fortress", "lat": 39.0438, "lng": -77.4874,
     "label": "ACME Ashburn DC", "customer_id": "acme-corp", "department": "Infrastructure"},
    {"id": "acme-nexus-ash-001", "tier": "nexus", "lat": 39.0538, "lng": -77.4774,
     "label": "ACME ML Cluster", "customer_id": "acme-corp", "department": "AI/ML"},
    # Europe
    {"id": "acme-guardian-lon-001", "tier": "guardian", "lat": 51.5074, "lng": -0.1278,
     "label": "ACME London Office", "customer_id": "acme-corp", "department": "Sales"},
    {"id": "acme-guardian-ber-001", "tier": "guardian", "lat": 52.5200, "lng": 13.4050,
     "label": "ACME Berlin Office", "customer_id": "acme-corp", "department": "Engineering"},
    {"id": "acme-fortress-ams-001", "tier": "fortress", "lat": 52.3676, "lng": 4.9041,
     "label": "ACME Amsterdam DC", "customer_id": "acme-corp", "department": "Infrastructure"},
    # Sentinels (IoT/Edge)
    {"id": "acme-sentinel-sf-001", "tier": "sentinel", "lat": 37.7649, "lng": -122.4294,
     "label": "ACME SF Lobby", "customer_id": "acme-corp", "department": "Security"},
    {"id": "acme-sentinel-sf-002", "tier": "sentinel", "lat": 37.7749, "lng": -122.4394,
     "label": "ACME SF Server Room", "customer_id": "acme-corp", "department": "Security"},
    {"id": "acme-sentinel-nyc-001", "tier": "sentinel", "lat": 40.7028, "lng": -74.0160,
     "label": "ACME NYC Lobby", "customer_id": "acme-corp", "department": "Security"},
    {"id": "acme-sentinel-lon-001", "tier": "sentinel", "lat": 51.4974, "lng": -0.1378,
     "label": "ACME London Lobby", "customer_id": "acme-corp", "department": "Security"},
    {"id": "acme-sentinel-ber-001", "tier": "sentinel", "lat": 52.5100, "lng": 13.4150,
     "label": "ACME Berlin Lobby", "customer_id": "acme-corp", "department": "Security"},
    {"id": "acme-sentinel-remote-001", "tier": "sentinel", "lat": 47.6062, "lng": -122.3321,
     "label": "ACME Remote Worker Seattle", "customer_id": "acme-corp", "department": "Engineering"},
    {"id": "acme-sentinel-remote-002", "tier": "sentinel", "lat": 33.7490, "lng": -84.3880,
     "label": "ACME Remote Worker Atlanta", "customer_id": "acme-corp", "department": "Sales"},

    # ==========================================================================
    # GLOBEX INDUSTRIES (12 nodes)
    # ==========================================================================
    # North America
    {"id": "globex-guardian-chi-001", "tier": "guardian", "lat": 41.8781, "lng": -87.6298,
     "label": "Globex Chicago HQ", "customer_id": "globex-inc", "department": "Operations"},
    {"id": "globex-guardian-det-001", "tier": "guardian", "lat": 42.3314, "lng": -83.0458,
     "label": "Globex Detroit Plant", "customer_id": "globex-inc", "department": "Manufacturing"},
    {"id": "globex-fortress-chi-001", "tier": "fortress", "lat": 41.8881, "lng": -87.6198,
     "label": "Globex Chicago DC", "customer_id": "globex-inc", "department": "Infrastructure"},
    # Asia Pacific
    {"id": "globex-guardian-tok-001", "tier": "guardian", "lat": 35.6762, "lng": 139.6503,
     "label": "Globex Tokyo Office", "customer_id": "globex-inc", "department": "Sales"},
    {"id": "globex-guardian-sha-001", "tier": "guardian", "lat": 31.2304, "lng": 121.4737,
     "label": "Globex Shanghai Plant", "customer_id": "globex-inc", "department": "Manufacturing"},
    {"id": "globex-fortress-sgp-001", "tier": "fortress", "lat": 1.3521, "lng": 103.8198,
     "label": "Globex Singapore DC", "customer_id": "globex-inc", "department": "Infrastructure"},
    # Sentinels
    {"id": "globex-sentinel-chi-001", "tier": "sentinel", "lat": 41.8681, "lng": -87.6398,
     "label": "Globex Chicago Factory Floor", "customer_id": "globex-inc", "department": "Manufacturing"},
    {"id": "globex-sentinel-chi-002", "tier": "sentinel", "lat": 41.8581, "lng": -87.6498,
     "label": "Globex Chicago Warehouse", "customer_id": "globex-inc", "department": "Logistics"},
    {"id": "globex-sentinel-det-001", "tier": "sentinel", "lat": 42.3214, "lng": -83.0558,
     "label": "Globex Detroit Line A", "customer_id": "globex-inc", "department": "Manufacturing"},
    {"id": "globex-sentinel-det-002", "tier": "sentinel", "lat": 42.3114, "lng": -83.0658,
     "label": "Globex Detroit Line B", "customer_id": "globex-inc", "department": "Manufacturing"},
    {"id": "globex-sentinel-sha-001", "tier": "sentinel", "lat": 31.2204, "lng": 121.4837,
     "label": "Globex Shanghai Factory", "customer_id": "globex-inc", "department": "Manufacturing"},
    {"id": "globex-sentinel-tok-001", "tier": "sentinel", "lat": 35.6662, "lng": 139.6603,
     "label": "Globex Tokyo Warehouse", "customer_id": "globex-inc", "department": "Logistics"},

    # ==========================================================================
    # INITECH SYSTEMS (15 nodes - Financial Services)
    # ==========================================================================
    # Europe HQ
    {"id": "initech-guardian-lon-001", "tier": "guardian", "lat": 51.5174, "lng": -0.0878,
     "label": "Initech London HQ", "customer_id": "initech-systems", "department": "Trading"},
    {"id": "initech-guardian-lon-002", "tier": "guardian", "lat": 51.5274, "lng": -0.0778,
     "label": "Initech Canary Wharf", "customer_id": "initech-systems", "department": "Trading"},
    {"id": "initech-fortress-lon-001", "tier": "fortress", "lat": 51.5074, "lng": -0.0978,
     "label": "Initech London DC Primary", "customer_id": "initech-systems", "department": "Infrastructure"},
    {"id": "initech-fortress-lon-002", "tier": "fortress", "lat": 51.4974, "lng": -0.1078,
     "label": "Initech London DC Backup", "customer_id": "initech-systems", "department": "Infrastructure"},
    {"id": "initech-nexus-lon-001", "tier": "nexus", "lat": 51.5374, "lng": -0.0678,
     "label": "Initech Algo Trading Cluster", "customer_id": "initech-systems", "department": "Trading"},
    # Frankfurt (EU regulations)
    {"id": "initech-guardian-fra-001", "tier": "guardian", "lat": 50.1109, "lng": 8.6821,
     "label": "Initech Frankfurt Office", "customer_id": "initech-systems", "department": "Compliance"},
    {"id": "initech-fortress-fra-001", "tier": "fortress", "lat": 50.1209, "lng": 8.6721,
     "label": "Initech Frankfurt DC", "customer_id": "initech-systems", "department": "Infrastructure"},
    # North America
    {"id": "initech-guardian-nyc-001", "tier": "guardian", "lat": 40.7580, "lng": -73.9855,
     "label": "Initech Wall Street", "customer_id": "initech-systems", "department": "Trading"},
    {"id": "initech-fortress-nj-001", "tier": "fortress", "lat": 40.7357, "lng": -74.1724,
     "label": "Initech NJ Data Center", "customer_id": "initech-systems", "department": "Infrastructure"},
    {"id": "initech-nexus-nj-001", "tier": "nexus", "lat": 40.7257, "lng": -74.1824,
     "label": "Initech HFT Cluster", "customer_id": "initech-systems", "department": "Trading"},
    # Sentinels
    {"id": "initech-sentinel-lon-001", "tier": "sentinel", "lat": 51.5074, "lng": -0.0878,
     "label": "Initech London Trading Floor", "customer_id": "initech-systems", "department": "Security"},
    {"id": "initech-sentinel-lon-002", "tier": "sentinel", "lat": 51.5174, "lng": -0.0778,
     "label": "Initech CW Trading Floor", "customer_id": "initech-systems", "department": "Security"},
    {"id": "initech-sentinel-nyc-001", "tier": "sentinel", "lat": 40.7480, "lng": -73.9955,
     "label": "Initech NYSE Colocation", "customer_id": "initech-systems", "department": "Trading"},
    {"id": "initech-sentinel-fra-001", "tier": "sentinel", "lat": 50.1009, "lng": 8.6921,
     "label": "Initech Eurex Colocation", "customer_id": "initech-systems", "department": "Trading"},
    {"id": "initech-sentinel-chi-001", "tier": "sentinel", "lat": 41.8825, "lng": -87.6234,
     "label": "Initech CME Colocation", "customer_id": "initech-systems", "department": "Trading"},

    # ==========================================================================
    # WAYNE ENTERPRISES (18 nodes - Global Conglomerate)
    # ==========================================================================
    # North America
    {"id": "wayne-guardian-got-001", "tier": "guardian", "lat": 40.7484, "lng": -73.9857,
     "label": "Wayne Tower HQ", "customer_id": "wayne-enterprises", "department": "Executive"},
    {"id": "wayne-guardian-got-002", "tier": "guardian", "lat": 40.7384, "lng": -73.9957,
     "label": "Wayne Applied Sciences", "customer_id": "wayne-enterprises", "department": "R&D"},
    {"id": "wayne-fortress-got-001", "tier": "fortress", "lat": 40.7284, "lng": -74.0057,
     "label": "Wayne Secure Facility", "customer_id": "wayne-enterprises", "department": "Infrastructure"},
    {"id": "wayne-nexus-got-001", "tier": "nexus", "lat": 40.7184, "lng": -74.0157,
     "label": "Wayne Research Computing", "customer_id": "wayne-enterprises", "department": "R&D"},
    {"id": "wayne-guardian-la-001", "tier": "guardian", "lat": 34.0522, "lng": -118.2437,
     "label": "Wayne LA Office", "customer_id": "wayne-enterprises", "department": "Entertainment"},
    {"id": "wayne-guardian-chi-001", "tier": "guardian", "lat": 41.8781, "lng": -87.6298,
     "label": "Wayne Chicago Office", "customer_id": "wayne-enterprises", "department": "Finance"},
    # Europe
    {"id": "wayne-guardian-lon-001", "tier": "guardian", "lat": 51.5174, "lng": -0.1178,
     "label": "Wayne London HQ", "customer_id": "wayne-enterprises", "department": "EMEA"},
    {"id": "wayne-guardian-par-001", "tier": "guardian", "lat": 48.8566, "lng": 2.3522,
     "label": "Wayne Paris Office", "customer_id": "wayne-enterprises", "department": "Luxury"},
    {"id": "wayne-fortress-ams-001", "tier": "fortress", "lat": 52.3676, "lng": 4.9041,
     "label": "Wayne EU Data Center", "customer_id": "wayne-enterprises", "department": "Infrastructure"},
    # Asia Pacific
    {"id": "wayne-guardian-tok-001", "tier": "guardian", "lat": 35.6762, "lng": 139.6503,
     "label": "Wayne Tokyo Office", "customer_id": "wayne-enterprises", "department": "APAC"},
    {"id": "wayne-guardian-hk-001", "tier": "guardian", "lat": 22.3193, "lng": 114.1694,
     "label": "Wayne Hong Kong Office", "customer_id": "wayne-enterprises", "department": "Finance"},
    {"id": "wayne-fortress-sgp-001", "tier": "fortress", "lat": 1.3521, "lng": 103.8198,
     "label": "Wayne APAC Data Center", "customer_id": "wayne-enterprises", "department": "Infrastructure"},
    # Sentinels
    {"id": "wayne-sentinel-got-001", "tier": "sentinel", "lat": 40.7584, "lng": -73.9757,
     "label": "Wayne Tower Security", "customer_id": "wayne-enterprises", "department": "Security"},
    {"id": "wayne-sentinel-got-002", "tier": "sentinel", "lat": 40.7284, "lng": -73.9857,
     "label": "Wayne Labs Security", "customer_id": "wayne-enterprises", "department": "Security"},
    {"id": "wayne-sentinel-got-003", "tier": "sentinel", "lat": 40.7184, "lng": -73.9957,
     "label": "Wayne Vault", "customer_id": "wayne-enterprises", "department": "Security"},
    {"id": "wayne-sentinel-lon-001", "tier": "sentinel", "lat": 51.5074, "lng": -0.1278,
     "label": "Wayne London Security", "customer_id": "wayne-enterprises", "department": "Security"},
    {"id": "wayne-sentinel-tok-001", "tier": "sentinel", "lat": 35.6662, "lng": 139.6603,
     "label": "Wayne Tokyo Security", "customer_id": "wayne-enterprises", "department": "Security"},
    {"id": "wayne-sentinel-hk-001", "tier": "sentinel", "lat": 22.3093, "lng": 114.1794,
     "label": "Wayne HK Security", "customer_id": "wayne-enterprises", "department": "Security"},

    # ==========================================================================
    # STARK INDUSTRIES (15 nodes - Defense/Technology)
    # ==========================================================================
    # North America
    {"id": "stark-guardian-mal-001", "tier": "guardian", "lat": 34.0259, "lng": -118.7798,
     "label": "Stark Malibu HQ", "customer_id": "stark-industries", "department": "Executive"},
    {"id": "stark-guardian-ny-001", "tier": "guardian", "lat": 40.7614, "lng": -73.9776,
     "label": "Stark Tower NYC", "customer_id": "stark-industries", "department": "R&D"},
    {"id": "stark-fortress-ash-001", "tier": "fortress", "lat": 39.0338, "lng": -77.4974,
     "label": "Stark Secure Cloud", "customer_id": "stark-industries", "department": "Infrastructure"},
    {"id": "stark-nexus-mal-001", "tier": "nexus", "lat": 34.0359, "lng": -118.7698,
     "label": "Stark AI Research", "customer_id": "stark-industries", "department": "AI/ML"},
    {"id": "stark-nexus-ny-001", "tier": "nexus", "lat": 40.7714, "lng": -73.9676,
     "label": "Stark Tower Computing", "customer_id": "stark-industries", "department": "R&D"},
    # Europe
    {"id": "stark-guardian-lon-001", "tier": "guardian", "lat": 51.5274, "lng": -0.0878,
     "label": "Stark London Office", "customer_id": "stark-industries", "department": "Defense"},
    {"id": "stark-fortress-ber-001", "tier": "fortress", "lat": 52.5300, "lng": 13.3950,
     "label": "Stark Berlin Lab", "customer_id": "stark-industries", "department": "R&D"},
    # Asia Pacific
    {"id": "stark-guardian-tok-001", "tier": "guardian", "lat": 35.6862, "lng": 139.6403,
     "label": "Stark Tokyo Lab", "customer_id": "stark-industries", "department": "R&D"},
    {"id": "stark-guardian-syd-001", "tier": "guardian", "lat": -33.8688, "lng": 151.2093,
     "label": "Stark Sydney Office", "customer_id": "stark-industries", "department": "APAC"},
    # Sentinels
    {"id": "stark-sentinel-mal-001", "tier": "sentinel", "lat": 34.0159, "lng": -118.7898,
     "label": "Stark Malibu Perimeter", "customer_id": "stark-industries", "department": "Security"},
    {"id": "stark-sentinel-mal-002", "tier": "sentinel", "lat": 34.0459, "lng": -118.7598,
     "label": "Stark Lab Security", "customer_id": "stark-industries", "department": "Security"},
    {"id": "stark-sentinel-ny-001", "tier": "sentinel", "lat": 40.7514, "lng": -73.9876,
     "label": "Stark Tower Lobby", "customer_id": "stark-industries", "department": "Security"},
    {"id": "stark-sentinel-ny-002", "tier": "sentinel", "lat": 40.7814, "lng": -73.9576,
     "label": "Stark Tower Roof", "customer_id": "stark-industries", "department": "Security"},
    {"id": "stark-sentinel-lon-001", "tier": "sentinel", "lat": 51.5174, "lng": -0.0978,
     "label": "Stark London Security", "customer_id": "stark-industries", "department": "Security"},
    {"id": "stark-sentinel-tok-001", "tier": "sentinel", "lat": 35.6762, "lng": 139.6503,
     "label": "Stark Tokyo Security", "customer_id": "stark-industries", "department": "Security"},
]

# ============================================================================
# THREAT SOURCES (35+ locations with threat profiles)
# ============================================================================

THREAT_SOURCES: List[Dict[str, Any]] = [
    # APT Groups - China
    {"lat": 39.9042, "lng": 116.4074, "label": "Beijing", "threat_level": "high", "profile": "apt"},
    {"lat": 31.2304, "lng": 121.4737, "label": "Shanghai", "threat_level": "high", "profile": "apt"},
    {"lat": 22.5431, "lng": 114.0579, "label": "Shenzhen", "threat_level": "high", "profile": "apt"},
    {"lat": 23.1291, "lng": 113.2644, "label": "Guangzhou", "threat_level": "medium", "profile": "apt"},
    {"lat": 30.5728, "lng": 104.0668, "label": "Chengdu", "threat_level": "medium", "profile": "apt"},

    # APT Groups - Russia
    {"lat": 55.7558, "lng": 37.6173, "label": "Moscow", "threat_level": "critical", "profile": "apt"},
    {"lat": 59.9343, "lng": 30.3351, "label": "St. Petersburg", "threat_level": "high", "profile": "apt"},
    {"lat": 56.8389, "lng": 60.6057, "label": "Yekaterinburg", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 55.0084, "lng": 82.9357, "label": "Novosibirsk", "threat_level": "medium", "profile": "cybercrime"},

    # State Actors - Iran
    {"lat": 35.6892, "lng": 51.3890, "label": "Tehran", "threat_level": "high", "profile": "apt"},
    {"lat": 32.6546, "lng": 51.6680, "label": "Isfahan", "threat_level": "medium", "profile": "apt"},

    # State Actors - North Korea
    {"lat": 39.0392, "lng": 125.7625, "label": "Pyongyang", "threat_level": "critical", "profile": "apt"},

    # Cybercrime Hotspots - Southeast Asia
    {"lat": 37.5665, "lng": 126.9780, "label": "Seoul", "threat_level": "low", "profile": "mixed"},
    {"lat": 25.0330, "lng": 121.5654, "label": "Taipei", "threat_level": "low", "profile": "mixed"},
    {"lat": 14.5995, "lng": 120.9842, "label": "Manila", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 10.8231, "lng": 106.6297, "label": "Ho Chi Minh City", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 13.7563, "lng": 100.5018, "label": "Bangkok", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 3.1390, "lng": 101.6869, "label": "Kuala Lumpur", "threat_level": "medium", "profile": "cybercrime"},

    # Cybercrime - South Asia
    {"lat": 19.0760, "lng": 72.8777, "label": "Mumbai", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 28.6139, "lng": 77.2090, "label": "New Delhi", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 24.8607, "lng": 67.0011, "label": "Karachi", "threat_level": "high", "profile": "cybercrime"},
    {"lat": 23.8103, "lng": 90.4125, "label": "Dhaka", "threat_level": "medium", "profile": "cybercrime"},

    # Cybercrime - South America
    {"lat": -23.5505, "lng": -46.6333, "label": "Sao Paulo", "threat_level": "high", "profile": "cybercrime"},
    {"lat": -34.6037, "lng": -58.3816, "label": "Buenos Aires", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 4.7110, "lng": -74.0721, "label": "Bogota", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": -12.0464, "lng": -77.0428, "label": "Lima", "threat_level": "medium", "profile": "cybercrime"},

    # Cybercrime - Africa
    {"lat": 6.5244, "lng": 3.3792, "label": "Lagos", "threat_level": "high", "profile": "scam"},
    {"lat": -26.2041, "lng": 28.0473, "label": "Johannesburg", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 30.0444, "lng": 31.2357, "label": "Cairo", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": -1.2921, "lng": 36.8219, "label": "Nairobi", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 33.8869, "lng": 9.5375, "label": "Tunis", "threat_level": "medium", "profile": "cybercrime"},

    # Eastern Europe Cybercrime
    {"lat": 50.4501, "lng": 30.5234, "label": "Kyiv", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 44.4268, "lng": 26.1025, "label": "Bucharest", "threat_level": "high", "profile": "cybercrime"},
    {"lat": 42.6977, "lng": 23.3219, "label": "Sofia", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 41.9981, "lng": 21.4254, "label": "Skopje", "threat_level": "medium", "profile": "cybercrime"},
    {"lat": 53.9006, "lng": 27.5590, "label": "Minsk", "threat_level": "high", "profile": "apt"},
]

# ============================================================================
# ATTACK TYPES (25+ types with detailed metadata)
# ============================================================================

ATTACK_TYPES = [
    # DDoS Attacks (weight influences frequency)
    ("ddos_volumetric", 0.75, "Volumetric DDoS flood", "ddos", 3.0),
    ("ddos_amplification", 0.80, "DNS/NTP amplification attack", "ddos", 2.5),
    ("ddos_slowloris", 0.55, "Slowloris connection exhaustion", "ddos", 2.0),
    ("ddos_http_flood", 0.70, "HTTP flood attack", "ddos", 2.5),
    ("ddos_syn_flood", 0.65, "SYN flood attack", "ddos", 2.0),

    # Scanning & Reconnaissance
    ("port_scan", 0.30, "Port scanning reconnaissance", "scan", 4.0),
    ("vuln_scan", 0.40, "Vulnerability scanner detected", "scan", 3.0),
    ("service_enum", 0.35, "Service enumeration attempt", "scan", 2.5),
    ("network_mapping", 0.25, "Network topology mapping", "scan", 1.5),

    # Brute Force
    ("brute_force_ssh", 0.50, "SSH brute force attack", "bruteforce", 3.0),
    ("brute_force_rdp", 0.55, "RDP brute force attack", "bruteforce", 2.5),
    ("credential_stuffing", 0.60, "Credential stuffing attack", "bruteforce", 2.0),
    ("password_spray", 0.45, "Password spraying attack", "bruteforce", 1.5),

    # Malware & C2
    ("malware_c2", 0.90, "Malware C2 communication", "malware", 1.5),
    ("ransomware_beacon", 0.95, "Ransomware beacon detected", "malware", 1.0),
    ("botnet_activity", 0.85, "Botnet activity detected", "malware", 1.5),
    ("cryptominer", 0.70, "Cryptominer detected", "malware", 1.0),
    ("trojan_callback", 0.85, "Trojan callback detected", "malware", 1.0),

    # Web Application Attacks
    ("sql_injection", 0.65, "SQL injection attempt", "web", 2.0),
    ("xss_attempt", 0.45, "Cross-site scripting attempt", "web", 2.5),
    ("rfi_lfi", 0.70, "Remote/Local file inclusion", "web", 1.5),
    ("path_traversal", 0.55, "Path traversal attempt", "web", 2.0),
    ("csrf_attack", 0.40, "Cross-site request forgery", "web", 1.5),
    ("xxe_attack", 0.60, "XML external entity attack", "web", 1.0),

    # API Attacks
    ("api_abuse", 0.50, "API rate limit abuse", "api", 2.0),
    ("broken_auth", 0.65, "Authentication bypass attempt", "api", 1.5),
    ("idor_attempt", 0.55, "Insecure direct object reference", "api", 1.5),

    # Zero-Day & Advanced
    ("zero_day_indicator", 0.95, "Potential zero-day exploit", "advanced", 0.5),
    ("unknown_exploit", 0.80, "Unknown exploitation pattern", "advanced", 0.5),
    ("supply_chain", 0.90, "Supply chain compromise indicator", "advanced", 0.3),
]

# ============================================================================
# MITIGATION METHODS
# ============================================================================

MITIGATION_METHODS = [
    ("xdp_drop", 1, 10, "XDP/eBPF kernel-level drop"),
    ("rate_limit", 5, 30, "Rate limiting applied"),
    ("geo_block", 2, 15, "Geographic blocking"),
    ("signature_match", 10, 50, "IDS/IPS signature match"),
    ("ml_detection", 15, 80, "ML model detection"),
    ("anomaly_block", 20, 100, "Anomaly-based blocking"),
    ("reputation_block", 5, 25, "IP reputation blocking"),
    ("behavior_block", 25, 150, "Behavioral analysis block"),
    ("captcha_challenge", 50, 200, "CAPTCHA challenge issued"),
    ("honeypot_redirect", 30, 120, "Honeypot redirection"),
    ("waf_block", 8, 40, "WAF rule triggered"),
    ("threat_intel_block", 3, 20, "Threat intel match"),
]

# ============================================================================
# DEMO DATA GENERATOR - Enterprise Scale
# ============================================================================


class DemoDataGenerator:
    """Generates enterprise-scale demo events for Cortex visualization."""

    def __init__(self):
        self.event_counter = 0
        self.nodes = HOOKPROBE_NODES.copy()
        self.organizations = DEMO_ORGANIZATIONS.copy()

        # Initialize nodes with health data
        for node in self.nodes:
            node["qsecbit"] = random.uniform(0.1, 0.4)
            node["status"] = "green"
            node["online"] = True
            node["last_heartbeat"] = datetime.utcnow()

        # Track state for realistic patterns
        self._recent_attacks: List[Dict] = []
        self._active_campaigns: Dict[str, Dict] = {}  # source -> campaign info
        self._targeted_nodes: Dict[str, int] = {}  # node_id -> attack count
        self._mesh_connections: List[Dict] = []
        self._generate_mesh_connections()

        # Statistics
        self._stats = {
            "total_attacks": 0,
            "total_repelled": 0,
            "attacks_by_type": {},
            "attacks_by_source": {},
        }

    def _generate_mesh_connections(self):
        """Generate mesh connections between nodes."""
        # Connect nodes by region/tier
        for i, node in enumerate(self.nodes):
            # Each node connects to 2-4 nearby nodes
            num_connections = random.randint(2, 4)
            nearby = sorted(
                self.nodes,
                key=lambda n: self._distance(node, n)
            )[1:num_connections + 1]

            for target in nearby:
                if not any(
                    c["source"] == node["id"] and c["target"] == target["id"]
                    for c in self._mesh_connections
                ):
                    self._mesh_connections.append({
                        "source": node["id"],
                        "target": target["id"],
                        "latency": random.randint(10, 150),
                        "bandwidth": random.randint(100, 5000),
                    })

    def _distance(self, node1: Dict, node2: Dict) -> float:
        """Calculate approximate distance between nodes."""
        lat1, lng1 = node1["lat"], node1["lng"]
        lat2, lng2 = node2["lat"], node2["lng"]
        return math.sqrt((lat2 - lat1) ** 2 + (lng2 - lng1) ** 2)

    def generate_event(self) -> Dict[str, Any]:
        """Generate a random event with realistic distribution."""
        self.event_counter += 1

        # Weighted event distribution:
        # 50% attacks, 30% repelled, 12% node status, 5% qsecbit, 3% mesh update
        roll = random.random()

        if roll < 0.50:
            return self._generate_attack()
        elif roll < 0.80:
            return self._generate_repelled()
        elif roll < 0.92:
            return self._generate_node_status()
        elif roll < 0.97:
            return self._generate_qsecbit_update()
        else:
            return self._generate_mesh_update()

    def _generate_attack(self) -> Dict[str, Any]:
        """Generate an attack_detected event with campaign awareness."""
        # Select threat source based on profile weights
        source = self._select_threat_source()
        target = self._select_target()

        # Select attack type with category weighting
        attack_name, base_severity, description, category, weight = self._select_attack_type()

        # Campaign persistence (40% chance to continue existing campaign)
        campaign_id = None
        if self._active_campaigns and random.random() < 0.4:
            campaign_id = random.choice(list(self._active_campaigns.keys()))
            campaign = self._active_campaigns[campaign_id]
            source = campaign["source"]
            campaign["attack_count"] += 1
        else:
            # Start new campaign (20% chance)
            if random.random() < 0.2:
                campaign_id = f"campaign-{self.event_counter}"
                self._active_campaigns[campaign_id] = {
                    "source": source,
                    "attack_count": 1,
                    "started": datetime.utcnow(),
                    "category": category,
                }

        # Track targeted node
        self._targeted_nodes[target["id"]] = self._targeted_nodes.get(target["id"], 0) + 1

        # Vary severity based on threat profile
        severity_modifier = {"critical": 0.15, "high": 0.1, "medium": 0.0, "low": -0.1}.get(
            source.get("threat_level", "medium"), 0
        )
        severity = max(0.1, min(1.0, base_severity + severity_modifier + random.uniform(-0.1, 0.1)))

        self._stats["total_attacks"] += 1
        self._stats["attacks_by_type"][category] = self._stats["attacks_by_type"].get(category, 0) + 1
        self._stats["attacks_by_source"][source["label"]] = self._stats["attacks_by_source"].get(source["label"], 0) + 1

        event = {
            "type": "attack_detected",
            "id": f"atk-{self.event_counter}",
            "source": {
                "lat": source["lat"],
                "lng": source["lng"],
                "label": source["label"],
                "threat_level": source.get("threat_level", "medium"),
                "profile": source.get("profile", "unknown"),
            },
            "target": {
                "lat": target["lat"],
                "lng": target["lng"],
                "label": target["label"],
                "node_id": target["id"],
                "customer_id": target.get("customer_id", "unknown"),
                "department": target.get("department", ""),
            },
            "attack_type": attack_name,
            "category": category,
            "severity": round(severity, 3),
            "description": description,
            "campaign_id": campaign_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        self._recent_attacks.append(event)
        if len(self._recent_attacks) > 50:
            self._recent_attacks.pop(0)

        return event

    def _generate_repelled(self) -> Dict[str, Any]:
        """Generate an attack_repelled event."""
        source = self._select_threat_source()
        target = self._select_target()
        attack_name, base_severity, description, category, _ = self._select_attack_type()

        # Select mitigation method
        method_name, min_ms, max_ms, method_desc = random.choice(MITIGATION_METHODS)
        response_ms = random.randint(min_ms, max_ms)

        self._stats["total_repelled"] += 1

        return {
            "type": "attack_repelled",
            "id": f"rep-{self.event_counter}",
            "source": {
                "lat": source["lat"],
                "lng": source["lng"],
                "label": source["label"],
                "threat_level": source.get("threat_level", "medium"),
            },
            "target": {
                "lat": target["lat"],
                "lng": target["lng"],
                "label": target["label"],
                "node_id": target["id"],
                "customer_id": target.get("customer_id", "unknown"),
            },
            "attack_type": attack_name,
            "category": category,
            "description": description,
            "mitigation": method_name,
            "mitigation_desc": method_desc,
            "response_ms": response_ms,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _generate_node_status(self) -> Dict[str, Any]:
        """Generate node status update with realistic distribution."""
        nodes_status = []
        for node in self.nodes:
            # Update Qsecbit with some drift
            current = node.get("qsecbit", 0.2)
            drift = random.uniform(-0.05, 0.05)

            # Nodes under attack drift higher
            if node["id"] in self._targeted_nodes:
                attack_pressure = min(0.3, self._targeted_nodes[node["id"]] * 0.02)
                drift += attack_pressure
                # Decay attack count
                self._targeted_nodes[node["id"]] = max(0, self._targeted_nodes[node["id"]] - 1)

            new_qsecbit = max(0.05, min(0.95, current + drift))
            node["qsecbit"] = new_qsecbit

            # Determine status
            if new_qsecbit < 0.45:
                status = "green"
            elif new_qsecbit < 0.70:
                status = "amber"
            else:
                status = "red"
            node["status"] = status

            nodes_status.append({
                "id": node["id"],
                "tier": node["tier"],
                "lat": node["lat"],
                "lng": node["lng"],
                "label": node["label"],
                "customer_id": node.get("customer_id", ""),
                "department": node.get("department", ""),
                "qsecbit": round(new_qsecbit, 3),
                "status": status,
                "online": node.get("online", True),
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
        dnsxai = random.uniform(0.0, 0.2)

        # Calculate weighted score (matches real Qsecbit formula)
        score = (
            0.25 * drift +
            0.25 * attack_probability +
            0.20 * classifier_decay +
            0.15 * quantum_drift +
            0.15 * dnsxai
        )
        score = min(1.0, max(0.0, score))

        node["qsecbit"] = score
        if score < 0.45:
            rag_status = "GREEN"
            node["status"] = "green"
        elif score < 0.70:
            rag_status = "AMBER"
            node["status"] = "amber"
        else:
            rag_status = "RED"
            node["status"] = "red"

        return {
            "type": "qsecbit_update",
            "node_id": node["id"],
            "customer_id": node.get("customer_id", ""),
            "score": round(score, 4),
            "components": {
                "drift": round(drift, 4),
                "attack_probability": round(attack_probability, 4),
                "classifier_decay": round(classifier_decay, 4),
                "quantum_drift": round(quantum_drift, 4),
                "dnsxai": round(dnsxai, 4),
            },
            "rag_status": rag_status,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _generate_mesh_update(self) -> Dict[str, Any]:
        """Generate mesh connection update."""
        if not self._mesh_connections:
            return self._generate_node_status()

        conn = random.choice(self._mesh_connections)

        # Vary latency slightly
        conn["latency"] = max(5, conn["latency"] + random.randint(-10, 10))

        return {
            "type": "mesh_update",
            "connection": {
                "source": conn["source"],
                "target": conn["target"],
                "latency": conn["latency"],
                "bandwidth": conn["bandwidth"],
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def _select_threat_source(self) -> Dict[str, Any]:
        """Select a threat source with weighting based on threat level."""
        weights = []
        for source in THREAT_SOURCES:
            level = source.get("threat_level", "medium")
            weight = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}.get(level, 1.0)
            weights.append(weight)

        total = sum(weights)
        r = random.random() * total
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return THREAT_SOURCES[i]
        return random.choice(THREAT_SOURCES)

    def _select_target(self) -> Dict[str, Any]:
        """Select a target node with weighting based on tier (higher = more targeted)."""
        tier_weights = {"nexus": 3.0, "fortress": 2.5, "guardian": 2.0, "sentinel": 1.0}
        weights = [tier_weights.get(n["tier"], 1.0) for n in self.nodes]

        total = sum(weights)
        r = random.random() * total
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return self.nodes[i]
        return random.choice(self.nodes)

    def _select_attack_type(self) -> tuple:
        """Select an attack type with category-based weighting."""
        weights = [at[4] for at in ATTACK_TYPES]
        total = sum(weights)
        r = random.random() * total
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return ATTACK_TYPES[i]
        return random.choice(ATTACK_TYPES)

    def generate_burst(self, count: int = 10, source_label: str = None) -> List[Dict[str, Any]]:
        """Generate a coordinated attack burst (simulating DDoS campaign)."""
        events = []

        # Pick a single source for coordinated attack
        if source_label:
            source = next((s for s in THREAT_SOURCES if s["label"] == source_label), None)
        else:
            source = random.choice([s for s in THREAT_SOURCES if s.get("threat_level") in ["critical", "high"]])

        if not source:
            source = random.choice(THREAT_SOURCES)

        # Target multiple nodes from the same organization
        org = random.choice(DEMO_ORGANIZATIONS)
        targets = [n for n in self.nodes if n.get("customer_id") == org["id"]]
        if not targets:
            targets = self.nodes

        # Generate coordinated attacks
        for i in range(count):
            target = random.choice(targets)
            attack = random.choice(ATTACK_TYPES[:5])  # DDoS types

            events.append({
                "type": "attack_detected",
                "id": f"burst-{self.event_counter}-{i}",
                "source": {
                    "lat": source["lat"],
                    "lng": source["lng"],
                    "label": source["label"],
                    "threat_level": source.get("threat_level", "high"),
                },
                "target": {
                    "lat": target["lat"],
                    "lng": target["lng"],
                    "label": target["label"],
                    "node_id": target["id"],
                    "customer_id": target.get("customer_id", ""),
                },
                "attack_type": attack[0],
                "category": attack[3],
                "severity": min(1.0, attack[1] + random.uniform(0, 0.15)),
                "description": attack[2],
                "burst": True,
                "campaign_id": f"burst-{self.event_counter}",
                "timestamp": datetime.utcnow().isoformat()
            })
            self.event_counter += 1

        return events

    def get_full_snapshot(self) -> Dict[str, Any]:
        """Get a complete snapshot for initial page load."""
        node_status = self._generate_node_status()

        return {
            "type": "snapshot",
            "nodes": node_status["nodes"],
            "edges": self._mesh_connections,
            "stats": self.get_statistics(),
            "organizations": [
                {
                    "id": org["id"],
                    "name": org["name"],
                    "device_count": len([n for n in self.nodes if n.get("customer_id") == org["id"]]),
                }
                for org in self.organizations
            ],
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive demo statistics."""
        nodes_by_customer = {}
        nodes_by_tier = {"sentinel": 0, "guardian": 0, "fortress": 0, "nexus": 0}
        nodes_by_status = {"green": 0, "amber": 0, "red": 0}

        for node in self.nodes:
            tier = node["tier"]
            nodes_by_tier[tier] = nodes_by_tier.get(tier, 0) + 1

            status = node.get("status", "green")
            nodes_by_status[status] = nodes_by_status.get(status, 0) + 1

            customer = node.get("customer_id", "unknown")
            if customer not in nodes_by_customer:
                nodes_by_customer[customer] = 0
            nodes_by_customer[customer] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_organizations": len(self.organizations),
            "nodes_by_tier": nodes_by_tier,
            "nodes_by_status": nodes_by_status,
            "nodes_by_customer": nodes_by_customer,
            "threat_sources": len(THREAT_SOURCES),
            "attack_types": len(ATTACK_TYPES),
            "mesh_connections": len(self._mesh_connections),
            "events_generated": self.event_counter,
            "active_campaigns": len(self._active_campaigns),
            "attack_stats": {
                "total_attacks": self._stats["total_attacks"],
                "total_repelled": self._stats["total_repelled"],
                "repel_rate": (
                    self._stats["total_repelled"] / max(1, self._stats["total_attacks"] + self._stats["total_repelled"])
                ),
                "by_type": self._stats["attacks_by_type"],
                "top_sources": sorted(
                    self._stats["attacks_by_source"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10],
            },
        }

    def get_fleet_data(self, customer_filter: str = None) -> Dict[str, Any]:
        """Get fleet management data (for Phase 3 fleet panel)."""
        if customer_filter:
            nodes = [n for n in self.nodes if n.get("customer_id") == customer_filter]
        else:
            nodes = self.nodes

        # Group by customer
        customers = []
        for org in self.organizations:
            org_nodes = [n for n in nodes if n.get("customer_id") == org["id"]]
            if org_nodes:
                customers.append({
                    "id": org["id"],
                    "name": org["name"],
                    "device_count": len(org_nodes),
                    "online_count": sum(1 for n in org_nodes if n.get("online", True)),
                    "avg_qsecbit": sum(n.get("qsecbit", 0) for n in org_nodes) / len(org_nodes),
                    "worst_status": (
                        "red" if any(n.get("status") == "red" for n in org_nodes) else
                        "amber" if any(n.get("status") == "amber" for n in org_nodes) else
                        "green"
                    ),
                })

        return {
            "type": "fleet_data",
            "customers": customers,
            "devices": [
                {
                    "id": n["id"],
                    "tier": n["tier"],
                    "lat": n["lat"],
                    "lng": n["lng"],
                    "label": n["label"],
                    "customer_id": n.get("customer_id", ""),
                    "department": n.get("department", ""),
                    "qsecbit": round(n.get("qsecbit", 0.2), 3),
                    "status": n.get("status", "green"),
                    "online": n.get("online", True),
                }
                for n in nodes
            ],
            "stats": {
                "total_devices": len(nodes),
                "online_devices": sum(1 for n in nodes if n.get("online", True)),
                "avg_qsecbit": sum(n.get("qsecbit", 0) for n in nodes) / max(1, len(nodes)),
                "by_tier": {
                    "sentinel": len([n for n in nodes if n["tier"] == "sentinel"]),
                    "guardian": len([n for n in nodes if n["tier"] == "guardian"]),
                    "fortress": len([n for n in nodes if n["tier"] == "fortress"]),
                    "nexus": len([n for n in nodes if n["tier"] == "nexus"]),
                },
                "by_status": {
                    "green": len([n for n in nodes if n.get("status") == "green"]),
                    "amber": len([n for n in nodes if n.get("status") == "amber"]),
                    "red": len([n for n in nodes if n.get("status") == "red"]),
                },
            },
            "timestamp": datetime.utcnow().isoformat()
        }


if __name__ == "__main__":
    # Test the generator
    gen = DemoDataGenerator()
    import json

    print("=== Enterprise Demo Data Generator Test ===\n")
    print(f"Statistics: {json.dumps(gen.get_statistics(), indent=2, default=str)}\n")

    print("=== Sample Events ===\n")
    for i in range(5):
        event = gen.generate_event()
        print(f"Event {i + 1}: {event['type']}")
        if event["type"] in ["attack_detected", "attack_repelled"]:
            print(f"  Source: {event['source']['label']} -> Target: {event['target']['label']}")
            print(f"  Type: {event.get('attack_type')} | Severity: {event.get('severity', 'N/A')}")
        print()

    print("=== Fleet Data Sample ===")
    fleet = gen.get_fleet_data()
    print(f"Total Devices: {fleet['stats']['total_devices']}")
    print(f"Organizations: {len(fleet['customers'])}")
    for org in fleet['customers']:
        print(f"  - {org['name']}: {org['device_count']} devices ({org['worst_status']})")
