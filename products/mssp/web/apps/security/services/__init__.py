"""
Security Services - IDS/IPS Implementation

AIOCHI "Simple" Philosophy:
- Template-first, LLM-fallback for narratives
- Hybrid classifier (70% signature, 30% ML)
- Autonomous quarantine on high-confidence threats
"""

from .parsers import SuricataParser, ZeekParser
from .classifier import HybridClassifier
from .quarantine import QuarantineManager

__all__ = [
    'SuricataParser',
    'ZeekParser',
    'HybridClassifier',
    'QuarantineManager',
]
