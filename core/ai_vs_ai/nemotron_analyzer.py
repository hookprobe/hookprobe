#!/usr/bin/env python3
"""
Nemotron Security Analyzer

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Integration with NVIDIA Nemotron models via OpenRouter for advanced
security analysis including:
- Deep threat analysis and correlation
- Vulnerability assessment and prioritization
- AI-generated remediation recommendations
- Natural language threat hunting queries

Models:
- nvidia/nemotron-3-nano-30b-a3b (default)
- nvidia/nemotron-70b (for complex analysis)

Usage:
    analyzer = NemotronSecurityAnalyzer(api_key="sk-or-...")

    # Analyze a threat
    analysis = await analyzer.analyze_threat({
        'type': 'network_intrusion',
        'source_ip': '192.168.1.100',
        'indicators': [...]
    })

    # Generate mitigation
    mitigation = await analyzer.generate_mitigation(vulnerability)

    # Threat hunting
    results = await analyzer.hunt_threats("unusual outbound DNS", dsm_data)
"""

import json
import logging
import asyncio
import hashlib
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ThreatAnalysis:
    """Detailed threat analysis result."""
    threat_id: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    confidence: float
    classification: str
    summary: str
    technical_details: str
    iocs: List[Dict]  # Indicators of Compromise
    attack_vectors: List[str]
    mitre_attack_ids: List[str]
    recommended_actions: List[str]
    related_threats: List[str]
    timestamp: float


@dataclass
class MitigationPlan:
    """AI-generated mitigation plan."""
    vulnerability_id: str
    severity: str
    priority: int
    immediate_actions: List[str]
    short_term_actions: List[str]
    long_term_actions: List[str]
    detection_rules: List[str]
    affected_systems: List[str]
    estimated_effort: str  # 'hours', 'days', 'weeks'
    technical_guidance: str
    timestamp: float


@dataclass
class ThreatHuntResult:
    """Result of threat hunting query."""
    query: str
    findings: List[Dict]
    risk_score: float
    recommendations: List[str]
    follow_up_queries: List[str]
    execution_time: float
    timestamp: float


class NemotronSecurityAnalyzer:
    """
    NVIDIA Nemotron integration for vulnerability analysis.

    Uses Nemotron models via OpenRouter for:
    1. Deep threat analysis with context correlation
    2. Vulnerability prioritization and assessment
    3. AI-generated remediation guidance
    4. Natural language threat hunting
    """

    # OpenRouter API endpoint
    OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

    # Default model
    DEFAULT_MODEL = "nvidia/nemotron-3-nano-30b-a3b"

    # System prompts
    THREAT_ANALYSIS_PROMPT = """You are a senior security analyst specializing in threat detection and incident response. Analyze the provided security event and provide a comprehensive assessment including:

1. CLASSIFICATION: What type of attack/threat is this?
2. SEVERITY: Critical/High/Medium/Low and why
3. TECHNICAL ANALYSIS: What exactly is happening technically
4. INDICATORS: Extract all IOCs (IPs, domains, hashes, etc.)
5. MITRE ATT&CK: Map to relevant techniques
6. IMPACT: What is the potential business impact
7. RECOMMENDATIONS: Immediate actions to take

Be specific and technical. Provide actionable intelligence."""

    MITIGATION_PROMPT = """You are a security engineer specializing in vulnerability remediation. Given the vulnerability details, provide a comprehensive mitigation plan including:

1. IMMEDIATE ACTIONS: What to do right now (within hours)
2. SHORT-TERM: Actions for the next few days
3. LONG-TERM: Strategic improvements
4. DETECTION: How to detect exploitation attempts
5. VERIFICATION: How to verify the fix worked
6. COMPENSATING CONTROLS: If patching isn't immediately possible

Be specific with commands, configurations, and technical steps."""

    THREAT_HUNT_PROMPT = """You are a threat hunter analyzing security telemetry data. Given the query and data context, identify potential threats and anomalies. Look for:

1. Suspicious patterns or behaviors
2. Known attack indicators
3. Anomalies from baseline
4. Lateral movement signs
5. Data exfiltration indicators
6. Persistence mechanisms

Provide specific findings with evidence and recommended follow-up queries."""

    def __init__(
        self,
        openrouter_api_key: str,
        model: str = DEFAULT_MODEL,
        site_url: str = "https://hookprobe.com",
        site_name: str = "HookProbe Security Platform",
    ):
        """
        Initialize Nemotron security analyzer.

        Args:
            openrouter_api_key: OpenRouter API key
            model: Nemotron model ID
            site_url: Site URL for OpenRouter attribution
            site_name: Site name for OpenRouter attribution
        """
        self.api_key = openrouter_api_key
        self.model = model
        self.site_url = site_url
        self.site_name = site_name

        # Rate limiting
        self._last_request = 0
        self._min_request_interval = 1.0  # 1 second between requests

        # Statistics
        self._stats = {
            'analyses_performed': 0,
            'mitigations_generated': 0,
            'hunts_executed': 0,
            'tokens_used': 0,
            'errors': 0,
        }

        logger.info(f"[Nemotron] Analyzer initialized with model: {model}")

    async def _call_api(
        self,
        messages: List[Dict],
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> str:
        """
        Make API call to OpenRouter.

        Args:
            messages: Chat messages
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            Model response text
        """
        import aiohttp

        # Rate limiting
        elapsed = time.time() - self._last_request
        if elapsed < self._min_request_interval:
            await asyncio.sleep(self._min_request_interval - elapsed)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": self.site_url,
            "X-Title": self.site_name,
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.OPENROUTER_URL,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as response:
                    self._last_request = time.time()

                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"[Nemotron] API error: {response.status} - {error_text}")
                        self._stats['errors'] += 1
                        raise RuntimeError(f"API error: {response.status}")

                    data = await response.json()

                    # Track tokens
                    if 'usage' in data:
                        self._stats['tokens_used'] += data['usage'].get('total_tokens', 0)

                    return data['choices'][0]['message']['content']

        except asyncio.TimeoutError:
            logger.error("[Nemotron] API request timeout")
            self._stats['errors'] += 1
            raise
        except Exception as e:
            logger.error(f"[Nemotron] API request failed: {e}")
            self._stats['errors'] += 1
            raise

    async def analyze_threat(self, threat_context: Dict) -> ThreatAnalysis:
        """
        Perform deep analysis of detected threat.

        Args:
            threat_context: Dictionary containing threat details:
                - type: Threat type
                - source_ip: Source IP address
                - destination_ip: Destination IP
                - indicators: List of IOCs
                - raw_data: Raw event data
                - timeline: Event timeline

        Returns:
            Detailed threat analysis
        """
        # Format context for LLM
        context_text = f"""
SECURITY EVENT ANALYSIS REQUEST
================================
Type: {threat_context.get('type', 'unknown')}
Source IP: {threat_context.get('source_ip', 'N/A')}
Destination IP: {threat_context.get('destination_ip', 'N/A')}
Protocol: {threat_context.get('protocol', 'N/A')}
Port: {threat_context.get('port', 'N/A')}

INDICATORS:
{json.dumps(threat_context.get('indicators', []), indent=2)}

RAW DATA:
{json.dumps(threat_context.get('raw_data', {}), indent=2)[:2000]}

CONTEXT:
{threat_context.get('context', 'No additional context provided.')}
"""

        messages = [
            {"role": "system", "content": self.THREAT_ANALYSIS_PROMPT},
            {"role": "user", "content": context_text},
        ]

        response = await self._call_api(messages)
        self._stats['analyses_performed'] += 1

        # Parse response into structured analysis
        analysis = self._parse_threat_analysis(threat_context, response)

        logger.info(f"[Nemotron] Threat analysis complete: {analysis.threat_id} (severity: {analysis.severity})")

        return analysis

    def _parse_threat_analysis(self, context: Dict, response: str) -> ThreatAnalysis:
        """Parse LLM response into ThreatAnalysis structure."""
        # Generate threat ID
        threat_id = f"THREAT-{hashlib.sha256(json.dumps(context).encode()).hexdigest()[:12].upper()}"

        # Extract severity from response
        severity = 'medium'
        for level in ['critical', 'high', 'medium', 'low', 'info']:
            if level.upper() in response.upper():
                severity = level
                break

        # Extract MITRE ATT&CK IDs
        import re
        mitre_pattern = r'T\d{4}(?:\.\d{3})?'
        mitre_ids = re.findall(mitre_pattern, response)

        # Extract IOCs (simplified)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'

        ips = re.findall(ip_pattern, response)
        domains = re.findall(domain_pattern, response)

        iocs = []
        for ip in set(ips):
            iocs.append({'type': 'ip', 'value': ip})
        for domain in set(domains):
            if '.' in domain and not domain.endswith('.md'):
                iocs.append({'type': 'domain', 'value': domain})

        return ThreatAnalysis(
            threat_id=threat_id,
            severity=severity,
            confidence=0.85,  # Placeholder
            classification=context.get('type', 'unknown'),
            summary=response[:500],  # First 500 chars as summary
            technical_details=response,
            iocs=iocs[:20],  # Limit IOCs
            attack_vectors=context.get('attack_vectors', []),
            mitre_attack_ids=list(set(mitre_ids))[:10],
            recommended_actions=self._extract_recommendations(response),
            related_threats=[],
            timestamp=time.time(),
        )

    def _extract_recommendations(self, response: str) -> List[str]:
        """Extract actionable recommendations from response."""
        recommendations = []

        # Look for numbered or bulleted items after keywords
        lines = response.split('\n')
        in_recommendations = False

        for line in lines:
            line = line.strip()

            if any(kw in line.upper() for kw in ['RECOMMENDATION', 'ACTION', 'SHOULD', 'MUST']):
                in_recommendations = True

            if in_recommendations and line:
                # Extract numbered items
                if line[0].isdigit() or line.startswith('-') or line.startswith('*'):
                    clean_line = line.lstrip('0123456789.-* ')
                    if len(clean_line) > 10:
                        recommendations.append(clean_line[:200])

            if len(recommendations) >= 10:
                break

        return recommendations

    async def generate_mitigation(self, vulnerability: Dict) -> MitigationPlan:
        """
        Generate AI-powered remediation steps.

        Args:
            vulnerability: Dictionary containing vulnerability details:
                - cve_id: CVE identifier
                - severity: Severity level
                - affected_software: Affected software/systems
                - description: Vulnerability description
                - exploit_available: Whether public exploit exists

        Returns:
            Detailed mitigation plan
        """
        context_text = f"""
VULNERABILITY REMEDIATION REQUEST
=================================
CVE ID: {vulnerability.get('cve_id', 'N/A')}
Severity: {vulnerability.get('severity', 'unknown')}
CVSS Score: {vulnerability.get('cvss_score', 'N/A')}

AFFECTED SOFTWARE:
{json.dumps(vulnerability.get('affected_software', []), indent=2)}

DESCRIPTION:
{vulnerability.get('description', 'No description provided.')}

EXPLOIT STATUS:
Public Exploit: {vulnerability.get('exploit_available', 'Unknown')}
Actively Exploited: {vulnerability.get('actively_exploited', 'Unknown')}

ENVIRONMENT:
{json.dumps(vulnerability.get('environment', {}), indent=2)}

Please provide a comprehensive remediation plan.
"""

        messages = [
            {"role": "system", "content": self.MITIGATION_PROMPT},
            {"role": "user", "content": context_text},
        ]

        response = await self._call_api(messages)
        self._stats['mitigations_generated'] += 1

        # Parse response into mitigation plan
        plan = self._parse_mitigation_plan(vulnerability, response)

        logger.info(f"[Nemotron] Mitigation plan generated: {plan.vulnerability_id}")

        return plan

    def _parse_mitigation_plan(self, vulnerability: Dict, response: str) -> MitigationPlan:
        """Parse LLM response into MitigationPlan structure."""
        vuln_id = vulnerability.get('cve_id', f"VULN-{hashlib.sha256(json.dumps(vulnerability).encode()).hexdigest()[:8].upper()}")

        # Extract sections
        immediate = []
        short_term = []
        long_term = []
        detection = []

        current_section = None
        for line in response.split('\n'):
            line = line.strip()

            if 'IMMEDIATE' in line.upper():
                current_section = 'immediate'
            elif 'SHORT' in line.upper() and 'TERM' in line.upper():
                current_section = 'short_term'
            elif 'LONG' in line.upper() and 'TERM' in line.upper():
                current_section = 'long_term'
            elif 'DETECTION' in line.upper():
                current_section = 'detection'

            if current_section and line and (line[0].isdigit() or line.startswith('-')):
                clean_line = line.lstrip('0123456789.-* ')
                if len(clean_line) > 5:
                    if current_section == 'immediate':
                        immediate.append(clean_line)
                    elif current_section == 'short_term':
                        short_term.append(clean_line)
                    elif current_section == 'long_term':
                        long_term.append(clean_line)
                    elif current_section == 'detection':
                        detection.append(clean_line)

        # Determine priority based on severity
        severity = vulnerability.get('severity', 'medium').lower()
        priority_map = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4}
        priority = priority_map.get(severity, 3)

        return MitigationPlan(
            vulnerability_id=vuln_id,
            severity=severity,
            priority=priority,
            immediate_actions=immediate[:5],
            short_term_actions=short_term[:5],
            long_term_actions=long_term[:5],
            detection_rules=detection[:5],
            affected_systems=vulnerability.get('affected_software', []),
            estimated_effort='days' if severity in ['critical', 'high'] else 'weeks',
            technical_guidance=response,
            timestamp=time.time(),
        )

    async def hunt_threats(
        self,
        query: str,
        dsm_data: Dict,
        additional_context: str = "",
    ) -> ThreatHuntResult:
        """
        Natural language threat hunting.

        Args:
            query: Natural language hunt query
            dsm_data: DSM telemetry data context
            additional_context: Additional context for the hunt

        Returns:
            Threat hunt results
        """
        start_time = time.time()

        context_text = f"""
THREAT HUNTING QUERY
====================
Query: {query}

DATA CONTEXT (DSM Telemetry Summary):
- Time Range: {dsm_data.get('time_range', 'Last 24 hours')}
- Total Events: {dsm_data.get('total_events', 'N/A')}
- Unique Sources: {dsm_data.get('unique_sources', 'N/A')}
- Unique Destinations: {dsm_data.get('unique_destinations', 'N/A')}

TOP EVENTS BY TYPE:
{json.dumps(dsm_data.get('event_types', {}), indent=2)}

NETWORK FLOWS SAMPLE:
{json.dumps(dsm_data.get('network_flows', [])[:10], indent=2)}

ANOMALIES DETECTED:
{json.dumps(dsm_data.get('anomalies', [])[:5], indent=2)}

ADDITIONAL CONTEXT:
{additional_context}

Analyze this data in context of the query and identify potential threats.
"""

        messages = [
            {"role": "system", "content": self.THREAT_HUNT_PROMPT},
            {"role": "user", "content": context_text},
        ]

        response = await self._call_api(messages, temperature=0.4)
        self._stats['hunts_executed'] += 1

        execution_time = time.time() - start_time

        # Parse hunt results
        result = self._parse_hunt_result(query, response, execution_time)

        logger.info(f"[Nemotron] Threat hunt complete: {len(result.findings)} findings")

        return result

    def _parse_hunt_result(self, query: str, response: str, execution_time: float) -> ThreatHuntResult:
        """Parse LLM response into ThreatHuntResult structure."""
        findings = []
        recommendations = []
        follow_up = []

        # Extract findings (simplified parsing)
        lines = response.split('\n')
        current_section = None

        for line in lines:
            line = line.strip()

            if 'FINDING' in line.upper() or 'SUSPICIOUS' in line.upper():
                current_section = 'findings'
            elif 'RECOMMEND' in line.upper():
                current_section = 'recommendations'
            elif 'FOLLOW' in line.upper():
                current_section = 'follow_up'

            if current_section and line and (line[0].isdigit() or line.startswith('-')):
                clean_line = line.lstrip('0123456789.-* ')
                if len(clean_line) > 10:
                    if current_section == 'findings':
                        findings.append({'description': clean_line, 'confidence': 0.7})
                    elif current_section == 'recommendations':
                        recommendations.append(clean_line)
                    elif current_section == 'follow_up':
                        follow_up.append(clean_line)

        # Calculate risk score based on findings
        risk_score = min(1.0, len(findings) * 0.2)

        return ThreatHuntResult(
            query=query,
            findings=findings[:10],
            risk_score=risk_score,
            recommendations=recommendations[:5],
            follow_up_queries=follow_up[:5],
            execution_time=execution_time,
            timestamp=time.time(),
        )

    def get_stats(self) -> Dict:
        """Get analyzer statistics."""
        return self._stats.copy()


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    import os

    print("Nemotron Security Analyzer Demo")
    print("=" * 50)

    # Check for API key
    api_key = os.environ.get('OPENROUTER_API_KEY')
    if not api_key:
        print("\nWARNING: OPENROUTER_API_KEY not set")
        print("Set environment variable to test with real API")
        print("\nRunning in mock mode...")

        # Mock demo
        analyzer = NemotronSecurityAnalyzer(
            openrouter_api_key="mock-key",
            model="nvidia/nemotron-3-nano-30b-a3b",
        )

        print(f"\nAnalyzer initialized: {analyzer.model}")
        print(f"Stats: {analyzer.get_stats()}")

    else:
        async def demo():
            analyzer = NemotronSecurityAnalyzer(
                openrouter_api_key=api_key,
            )

            # Test threat analysis
            print("\nAnalyzing sample threat...")
            threat = {
                'type': 'network_intrusion',
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.50',
                'port': 445,
                'protocol': 'SMB',
                'indicators': [
                    {'type': 'behavior', 'value': 'multiple failed auth attempts'},
                    {'type': 'pattern', 'value': 'lateral movement signature'},
                ],
                'raw_data': {
                    'event_count': 150,
                    'time_window': '5 minutes',
                },
            }

            analysis = await analyzer.analyze_threat(threat)
            print(f"  Threat ID: {analysis.threat_id}")
            print(f"  Severity: {analysis.severity}")
            print(f"  MITRE: {analysis.mitre_attack_ids}")
            print(f"  Recommendations: {len(analysis.recommended_actions)}")

            print(f"\nStats: {analyzer.get_stats()}")

        asyncio.run(demo())

    print("\n✓ Nemotron analyzer demo complete")
