"""
dnsXai - AI-Powered DNS Protection for HookProbe

An innovative, forward-thinking ad blocking and DNS protection system
that uses machine learning to detect and block ads, trackers, and
malicious domains beyond traditional blocklists.

Key Features:
- ML-based domain classification (20 features, <1ms inference)
- CNAME uncloaking (detects first-party tracker masquerading)
- Federated learning (privacy-preserving collective intelligence)
- Multi-tier protection levels (5 levels from basic to full)
- Mesh intelligence sharing (one node's detection → everyone's protection)

Usage:
    from shared.dnsXai import DNSXai, ProtectionLevel

    # Create instance with protection level
    dnsxai = DNSXai(level=ProtectionLevel.STRONG)

    # Classify a domain
    result = dnsxai.classify("doubleclick.net")
    print(result.blocked)  # True

    # Start DNS resolver
    dnsxai.start_server(port=5353)

Author: HookProbe Team
Version: 5.0.0
License: MIT
"""

from .engine import (
    AIAdBlocker as DNSXai,
    AdBlockConfig as DNSXaiConfig,
    DomainCategory,
    ClassificationResult,
    DomainClassifier,
    DomainFeatureExtractor,
    CNAMEUncloaker,
    FederatedAdLearning,
)

from .mesh_intelligence import (
    AdMeshIntelligenceAgent,
    AdBlockQsecbitIntegration,
    AdIOC,
    AdIOCType,
    MeshAdIntelligence,
    create_ad_intelligence_system,
)

from .integration import (
    GuardianAdBlockAgent,
    AdBlockMetrics,
    patch_guardian_agent_with_adblock,
)

from enum import IntEnum


class ProtectionLevel(IntEnum):
    """
    DNS protection levels for dnsXai.

    Each level builds on the previous, adding more protection categories.
    Higher levels block more domains but may impact usability.
    """
    OFF = 0        # No blocking (passthrough mode)
    BASE = 1       # Ads + Malware (~130K domains)
    ENHANCED = 2   # + Fakenews (~132K domains)
    STRONG = 3     # + Gambling (~135K domains)
    MAXIMUM = 4    # + Adult content (~200K domains)
    FULL = 5       # + Social trackers (~250K domains)


# Version info
__version__ = "5.0.0"
__author__ = "HookProbe Team"
__all__ = [
    # Main classes
    "DNSXai",
    "DNSXaiConfig",
    "ProtectionLevel",

    # Classification
    "DomainCategory",
    "ClassificationResult",
    "DomainClassifier",
    "DomainFeatureExtractor",

    # CNAME detection
    "CNAMEUncloaker",

    # Federated learning
    "FederatedAdLearning",
    "AdMeshIntelligenceAgent",
    "AdIOC",
    "AdIOCType",
    "MeshAdIntelligence",

    # Qsecbit integration
    "AdBlockQsecbitIntegration",

    # Guardian integration
    "GuardianAdBlockAgent",
    "AdBlockMetrics",

    # Factory functions
    "create_ad_intelligence_system",
    "patch_guardian_agent_with_adblock",
]
