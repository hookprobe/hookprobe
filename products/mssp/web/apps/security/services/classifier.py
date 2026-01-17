"""
AIOCHI Hybrid Classifier - "Simple for Users, Powerful Underneath"

Philosophy:
- 70% Signature-based detection (fast, deterministic)
- 30% ML-based behavioral analysis (catches novel attacks)
- Template-first narratives (95% templates, 5% LLM fallback)
- Autonomous quarantine on high-confidence (>90%) threats

The classifier evaluates each event through both signature and ML pipelines,
then combines scores with weighted voting.
"""

import re
import math
import logging
from typing import Optional, Tuple
from dataclasses import dataclass
from collections import Counter

from django.db.models import Count
from django.utils import timezone

from .parsers import ParsedEvent

logger = logging.getLogger(__name__)


@dataclass
class ClassificationResult:
    """Result of hybrid classification"""
    confidence: float  # 0.0 - 1.0
    confidence_level: str  # low, medium, high, critical
    severity: str  # info, low, medium, high, critical
    attack_type: str
    classification_method: str  # signature, ml, hybrid
    signature_match: str  # SID if signature matched
    ml_features: dict  # Features used for ML classification
    should_quarantine: bool
    narrative: str  # Human-readable explanation


class HybridClassifier:
    """
    AIOCHI Hybrid Classifier

    Combines signature matching with simple ML features to classify
    security events and determine response actions.
    """

    # Signature weight in final score
    SIGNATURE_WEIGHT = 0.7
    ML_WEIGHT = 0.3

    # Confidence thresholds
    LOW_THRESHOLD = 0.5
    MEDIUM_THRESHOLD = 0.7
    HIGH_THRESHOLD = 0.85
    CRITICAL_THRESHOLD = 0.95

    # Auto-quarantine threshold
    AUTO_QUARANTINE_THRESHOLD = 0.90

    # Known attack signatures (SID: (pattern, severity, attack_type, description))
    SIGNATURES = {
        # Web attacks
        'WEB-001': (r'\.\./', 'high', 'path-traversal', 'Path traversal attempt'),
        'WEB-002': (r'(?i)union\s+select', 'critical', 'sql-injection', 'SQL injection (UNION)'),
        'WEB-003': (r"(?i)'\s*(or|and)\s*'", 'critical', 'sql-injection', 'SQL injection (OR/AND)'),
        'WEB-004': (r'(?i)<script[^>]*>', 'high', 'xss-attempt', 'Cross-site scripting attempt'),
        'WEB-005': (r'(?i)(cmd|exec|system)\s*\(', 'critical', 'command-injection', 'Command injection'),
        'WEB-006': (r'/etc/passwd', 'high', 'lfi-attempt', 'Local file inclusion'),
        'WEB-007': (r'(?i)eval\s*\(', 'critical', 'code-injection', 'Code injection (eval)'),

        # Scanner detection
        'SCAN-001': (r'(?i)(sqlmap|nikto|nmap|masscan|zgrab)', 'high', 'scanner-detected', 'Security scanner detected'),
        'SCAN-002': (r'(?i)dirbuster', 'medium', 'directory-brute', 'Directory bruteforce'),

        # Malware patterns
        'MAL-001': (r'(?i)powershell\s*-e', 'critical', 'powershell-encoded', 'Encoded PowerShell'),
        'MAL-002': (r'(?i)wget\s+.+\s*\|\s*bash', 'critical', 'dropper', 'Remote script execution'),

        # Network attacks
        'NET-001': (r'(?i)admin.*password', 'medium', 'credential-attempt', 'Credential stuffing'),
        'NET-002': (r'(?i)(root|admin):.*:', 'high', 'credential-leak', 'Credential in request'),
    }

    # Narrative templates (AIOCHI style - 95% templates)
    NARRATIVE_TEMPLATES = {
        'path-traversal': "Detected path traversal attempt from {src_ip} targeting {dst_ip}. The attacker attempted to access files outside the web root using '../' sequences.",
        'sql-injection': "SQL injection attack detected from {src_ip}. The request contained malicious SQL syntax attempting to manipulate database queries.",
        'xss-attempt': "Cross-site scripting (XSS) attempt from {src_ip}. The attacker tried to inject JavaScript code into the response.",
        'command-injection': "Command injection detected from {src_ip}. The attacker attempted to execute system commands through the application.",
        'scanner-detected': "Security scanner detected from {src_ip}. The user agent or request pattern matches known scanning tools.",
        'credential-attempt': "Potential credential stuffing from {src_ip}. Multiple authentication attempts with common username/password combinations.",
        'powershell-encoded': "Encoded PowerShell execution attempt from {src_ip}. This is commonly used to evade detection.",
        'default': "Security event detected from {src_ip} targeting {dst_ip}. Attack type: {attack_type}. Severity: {severity}.",
    }

    def __init__(self):
        self._ip_history = {}  # Simple in-memory tracking
        self._attack_counts = Counter()

    def classify(self, event: ParsedEvent) -> ClassificationResult:
        """
        Classify an event using hybrid signature + ML approach.

        Returns:
            ClassificationResult with confidence score and recommended action
        """
        # Phase 1: Signature matching (70% weight)
        sig_score, sig_match, sig_severity, sig_attack = self._signature_match(event)

        # Phase 2: ML feature extraction and scoring (30% weight)
        ml_features = self._extract_features(event)
        ml_score, ml_severity, ml_attack = self._ml_classify(ml_features, event)

        # Phase 3: Combine scores
        final_score = (sig_score * self.SIGNATURE_WEIGHT) + (ml_score * self.ML_WEIGHT)

        # Determine classification method
        if sig_score > 0.8:
            method = 'signature'
            final_severity = sig_severity
            final_attack = sig_attack
        elif ml_score > 0.8:
            method = 'ml'
            final_severity = ml_severity
            final_attack = ml_attack
        else:
            method = 'hybrid'
            # Use higher severity
            final_severity = self._max_severity(sig_severity, ml_severity, event.severity)
            final_attack = sig_attack if sig_score > ml_score else (ml_attack or event.attack_type)

        # Boost score for known high-severity events
        if event.signature_id and event.priority and event.priority <= 2:
            final_score = max(final_score, 0.85)

        # Determine confidence level
        confidence_level = self._score_to_level(final_score)

        # Should we auto-quarantine?
        should_quarantine = (
            final_score >= self.AUTO_QUARANTINE_THRESHOLD and
            final_severity in ('critical', 'high') and
            method in ('signature', 'hybrid')
        )

        # Generate narrative
        narrative = self._generate_narrative(
            event, final_attack, final_severity, method, sig_match
        )

        return ClassificationResult(
            confidence=round(final_score, 4),
            confidence_level=confidence_level,
            severity=final_severity,
            attack_type=final_attack,
            classification_method=method,
            signature_match=sig_match,
            ml_features=ml_features,
            should_quarantine=should_quarantine,
            narrative=narrative,
        )

    def _signature_match(self, event: ParsedEvent) -> Tuple[float, str, str, str]:
        """
        Check event against known signatures.

        Returns: (score, matched_sig_id, severity, attack_type)
        """
        # Build searchable text from event
        search_text = self._build_search_text(event)

        best_match = ('', 0.0, 'info', 'unknown')

        for sig_id, (pattern, severity, attack_type, desc) in self.SIGNATURES.items():
            try:
                if re.search(pattern, search_text):
                    # Full match = high confidence
                    score = 0.95
                    if score > best_match[1]:
                        best_match = (sig_id, score, severity, attack_type)
            except re.error:
                continue

        # Also check Suricata's own signature if present
        if event.signature_id:
            # Trust Suricata signatures
            score = 0.90
            if score > best_match[1]:
                severity = event.classification or 'medium'
                # Map Suricata classification to our severity
                severity = self._map_classification_to_severity(severity)
                best_match = (
                    f"SID:{event.signature_id}",
                    score,
                    severity,
                    event.classification or event.attack_type
                )

        return best_match[1], best_match[0], best_match[2], best_match[3]

    def _extract_features(self, event: ParsedEvent) -> dict:
        """
        Extract ML-relevant features from event.

        Simple features that work without a trained model:
        - Entropy of strings (high entropy = encoded/encrypted)
        - Byte ratios
        - Timing patterns
        - IP reputation (based on history)
        """
        features = {}

        # Feature 1: Description entropy
        if event.description:
            features['description_entropy'] = self._calculate_entropy(event.description)
            features['description_length'] = len(event.description)

        # Feature 2: Port analysis
        if event.dst_port:
            features['dst_port'] = event.dst_port
            features['is_common_port'] = event.dst_port in (80, 443, 22, 21, 25, 53, 3306, 5432)
            features['is_high_port'] = event.dst_port > 1024

        # Feature 3: Protocol
        features['protocol'] = event.protocol
        features['is_encrypted'] = event.protocol in ('tls', 'https', 'ssh')

        # Feature 4: IP history (simple reputation)
        src_key = event.src_ip
        if src_key not in self._ip_history:
            self._ip_history[src_key] = {'events': 0, 'attacks': 0, 'first_seen': timezone.now()}

        self._ip_history[src_key]['events'] += 1
        if event.severity in ('high', 'critical'):
            self._ip_history[src_key]['attacks'] += 1

        ip_info = self._ip_history[src_key]
        features['ip_event_count'] = ip_info['events']
        features['ip_attack_ratio'] = ip_info['attacks'] / max(ip_info['events'], 1)

        # Feature 5: Raw data analysis (if available)
        if event.raw_data:
            raw_str = str(event.raw_data)
            features['raw_entropy'] = self._calculate_entropy(raw_str[:1000])
            features['raw_length'] = len(raw_str)

        return features

    def _ml_classify(self, features: dict, event: ParsedEvent) -> Tuple[float, str, str]:
        """
        Simple ML-based classification using extracted features.

        This is a rule-based approximation of what a trained model would do.
        In production, this could be replaced with a real sklearn/pytorch model.

        Returns: (score, severity, attack_type)
        """
        score = 0.3  # Base score
        severity = 'info'
        attack_type = 'unknown'

        # High entropy in description suggests encoded payload
        if features.get('description_entropy', 0) > 4.5:
            score += 0.2
            severity = 'medium'
            attack_type = 'encoded-payload'

        # Repeated attacks from same IP
        if features.get('ip_attack_ratio', 0) > 0.5:
            score += 0.25
            severity = 'high'
            attack_type = 'repeat-attacker'

        # Many events from same IP in short time
        if features.get('ip_event_count', 0) > 50:
            score += 0.15
            severity = 'medium'
            attack_type = 'flood-attempt'

        # Unusual port
        if not features.get('is_common_port', True) and not features.get('is_encrypted', False):
            score += 0.1

        # Use event's own severity as hint
        severity_boost = {'critical': 0.3, 'high': 0.2, 'medium': 0.1, 'low': 0.05}
        score += severity_boost.get(event.severity, 0)

        # Cap score
        score = min(score, 0.95)

        # Inherit severity from event if we didn't set a higher one
        if event.severity in ('critical', 'high') and severity in ('info', 'low', 'medium'):
            severity = event.severity

        return score, severity, attack_type or event.attack_type

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        # Count character frequencies
        freq = Counter(text)
        length = len(text)

        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return entropy

    def _build_search_text(self, event: ParsedEvent) -> str:
        """Build searchable text from event for signature matching"""
        parts = [
            event.description,
            event.attack_type,
            str(event.raw_data) if event.raw_data else '',
        ]
        return ' '.join(filter(None, parts))

    def _map_classification_to_severity(self, classification: str) -> str:
        """Map Suricata classification to severity"""
        classification_lower = classification.lower()
        mappings = {
            'attempted-admin': 'critical',
            'successful-admin': 'critical',
            'trojan-activity': 'critical',
            'attempted-user': 'high',
            'successful-user': 'high',
            'web-application-attack': 'high',
            'shellcode-detect': 'critical',
            'attempted-dos': 'high',
            'denial-of-service': 'critical',
            'attempted-recon': 'medium',
            'suspicious': 'medium',
            'bad-unknown': 'medium',
            'misc-attack': 'medium',
            'network-scan': 'low',
            'not-suspicious': 'info',
            'policy-violation': 'low',
        }

        for key, severity in mappings.items():
            if key in classification_lower:
                return severity

        return 'medium'

    def _max_severity(self, *severities) -> str:
        """Return the highest severity from given severities"""
        order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
        max_sev = 'info'
        max_val = 0

        for sev in severities:
            if sev and order.get(sev, 0) > max_val:
                max_val = order[sev]
                max_sev = sev

        return max_sev

    def _score_to_level(self, score: float) -> str:
        """Convert numeric score to confidence level"""
        if score >= self.CRITICAL_THRESHOLD:
            return 'critical'
        elif score >= self.HIGH_THRESHOLD:
            return 'high'
        elif score >= self.MEDIUM_THRESHOLD:
            return 'medium'
        elif score >= self.LOW_THRESHOLD:
            return 'low'
        else:
            return 'low'

    def _generate_narrative(
        self,
        event: ParsedEvent,
        attack_type: str,
        severity: str,
        method: str,
        signature: str
    ) -> str:
        """
        Generate human-readable narrative using templates.

        AIOCHI philosophy: 95% templates, 5% dynamic.
        Templates are clear, consistent, and don't require LLM.
        """
        # Select template
        template = self.NARRATIVE_TEMPLATES.get(
            attack_type,
            self.NARRATIVE_TEMPLATES['default']
        )

        # Fill template
        try:
            narrative = template.format(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                attack_type=attack_type,
                severity=severity,
                signature=signature,
                method=method,
            )
        except KeyError:
            # Fallback to default
            narrative = self.NARRATIVE_TEMPLATES['default'].format(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                attack_type=attack_type,
                severity=severity,
            )

        # Add method info
        if method == 'signature':
            narrative += f" [Detected by signature: {signature}]"
        elif method == 'ml':
            narrative += " [Detected by behavioral analysis]"
        else:
            narrative += f" [Hybrid detection, signature: {signature or 'none'}]"

        return narrative
