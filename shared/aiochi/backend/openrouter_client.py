"""
AIOCHI OpenRouter AI Client
Dynamic playbook generation for unknown threats using free LLM models.

Philosophy: When we see a threat we don't have a playbook for,
ask AI for guidance and generate a response on the fly.

Supported Models (Free):
- meta-llama/llama-3.1-8b-instruct:free
- mistralai/mistral-7b-instruct:free
- google/gemma-2-9b-it:free
"""

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class AIPlaybook:
    """A dynamically generated playbook from AI."""
    alert_name: str
    mitre_id: str
    mitre_name: str
    severity: str
    steps: List[Dict[str, str]]
    ovs_commands: List[str]
    dns_blocks: List[str]
    owner_narrative: str
    technical_summary: str
    confidence: float
    model_used: str
    generation_time_ms: float


# System prompt for playbook generation
SYSTEM_PROMPT = """You are AIOCHI, a security AI protecting small businesses like flower shops, bakeries, and retail stores.

Your job is to analyze security alerts and create simple, actionable playbooks that a non-technical owner can understand.

IMPORTANT RULES:
1. Always identify the MITRE ATT&CK technique ID (e.g., T1566 for Phishing)
2. Keep explanations simple - imagine explaining to a grandmother who owns a flower shop
3. Provide specific OVS (Open vSwitch) commands using bridge name "FTS"
4. Suggest DNS blocking for malicious domains
5. Be protective but not paranoid - avoid blocking legitimate business traffic

OUTPUT FORMAT (strict JSON):
{
  "mitre_id": "T1234",
  "mitre_name": "Technique Name",
  "severity": "low|medium|high|critical",
  "steps": [
    {"order": 1, "action": "What to do", "reason": "Why"},
    {"order": 2, "action": "What to do", "reason": "Why"},
    {"order": 3, "action": "What to do", "reason": "Why"}
  ],
  "ovs_commands": [
    "ovs-ofctl add-flow FTS \"...\"",
    "ovs-ofctl add-flow FTS \"...\""
  ],
  "dns_blocks": ["malicious-domain.com"],
  "owner_narrative": "Simple explanation a flower shop owner would understand",
  "technical_summary": "Brief technical description for logs"
}"""


class OpenRouterClient:
    """
    OpenRouter AI Client for dynamic playbook generation.

    Uses free models to generate security playbooks when no
    predefined playbook matches the alert.
    """

    API_URL = "https://openrouter.ai/api/v1/chat/completions"

    # Free models to use (in order of preference)
    FREE_MODELS = [
        "meta-llama/llama-3.1-8b-instruct:free",
        "mistralai/mistral-7b-instruct:free",
        "google/gemma-2-9b-it:free",
    ]

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 30,
        cache_responses: bool = True,
    ):
        """
        Initialize OpenRouter client.

        Args:
            api_key: OpenRouter API key (or from OPENROUTER_API_KEY env)
            model: Preferred model (default: first free model)
            timeout: Request timeout in seconds
            cache_responses: Cache AI responses for identical alerts
        """
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self.model = model or self.FREE_MODELS[0]
        self.timeout = timeout
        self.cache_responses = cache_responses

        # Response cache (alert_hash -> AIPlaybook)
        self._cache: Dict[str, AIPlaybook] = {}
        self._cache_ttl = 3600  # 1 hour

        # Statistics
        self._stats = {
            "requests": 0,
            "cache_hits": 0,
            "errors": 0,
            "total_latency_ms": 0,
        }

        if not self.api_key:
            logger.warning("No OpenRouter API key configured. Dynamic playbooks disabled.")

    def generate_playbook(
        self,
        alert_name: str,
        device_type: str,
        src_ip: str = "",
        dst_ip: str = "",
        dst_port: int = 0,
        additional_context: str = "",
    ) -> Optional[AIPlaybook]:
        """
        Generate a dynamic playbook for an unknown alert.

        Args:
            alert_name: IDS alert signature or name
            device_type: Type of device (e.g., "POS terminal", "Employee laptop")
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            additional_context: Any additional context

        Returns:
            AIPlaybook or None if generation failed
        """
        if not self.api_key:
            logger.warning("Cannot generate playbook: No API key")
            return None

        # Check cache
        cache_key = f"{alert_name}:{device_type}:{dst_port}"
        if self.cache_responses and cache_key in self._cache:
            self._stats["cache_hits"] += 1
            return self._cache[cache_key]

        # Build prompt
        user_prompt = self._build_prompt(
            alert_name, device_type, src_ip, dst_ip, dst_port, additional_context
        )

        # Call API
        start_time = time.time()
        try:
            response = self._call_api(user_prompt)
            latency_ms = (time.time() - start_time) * 1000

            if response:
                playbook = self._parse_response(
                    response, alert_name, latency_ms
                )

                if playbook and self.cache_responses:
                    self._cache[cache_key] = playbook

                return playbook

        except Exception as e:
            logger.error(f"Playbook generation failed: {e}")
            self._stats["errors"] += 1

        return None

    def get_quick_advice(self, alert_name: str) -> str:
        """
        Get quick one-liner advice for an alert (no full playbook).

        Args:
            alert_name: Alert signature

        Returns:
            Quick advice string
        """
        if not self.api_key:
            return "Check your security settings and monitor this device."

        prompt = f"In ONE sentence, what should a flower shop owner do about this security alert: {alert_name}"

        try:
            response = self._call_api(prompt, max_tokens=100)
            return response or "Monitor the situation and contact support if it continues."
        except Exception:
            return "Monitor the situation and contact support if it continues."

    def explain_mitre(self, technique_id: str) -> str:
        """
        Get a simple explanation of a MITRE ATT&CK technique.

        Args:
            technique_id: MITRE ID (e.g., T1566)

        Returns:
            Simple explanation
        """
        if not self.api_key:
            return f"Security technique {technique_id}"

        prompt = f"Explain MITRE ATT&CK technique {technique_id} in simple terms a flower shop owner would understand. One paragraph max."

        try:
            response = self._call_api(prompt, max_tokens=200)
            return response or f"Security technique {technique_id}"
        except Exception:
            return f"Security technique {technique_id}"

    def _build_prompt(
        self,
        alert_name: str,
        device_type: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        additional_context: str,
    ) -> str:
        """Build the user prompt for playbook generation."""
        prompt_parts = [
            f"I am a security engine for a small business (flower shop).",
            f"I just received an IDS alert: \"{alert_name}\"",
            f"The affected device is a: {device_type}",
        ]

        if src_ip:
            prompt_parts.append(f"Source IP: {src_ip}")
        if dst_ip:
            prompt_parts.append(f"Destination IP: {dst_ip}")
        if dst_port:
            prompt_parts.append(f"Destination Port: {dst_port}")
        if additional_context:
            prompt_parts.append(f"Additional context: {additional_context}")

        prompt_parts.append(
            "Map this to a MITRE ATT&CK ID and provide a 3-step mitigation playbook "
            "using OVS (Open vSwitch) and DNS blocking. Keep it simple for a non-technical owner."
        )

        return "\n".join(prompt_parts)

    def _call_api(
        self,
        user_prompt: str,
        max_tokens: int = 1000,
    ) -> Optional[str]:
        """Call the OpenRouter API."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://hookprobe.com/aiochi",
            "X-Title": "AIOCHI Security Engine",
        }

        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3,  # Low temperature for consistent responses
        }

        self._stats["requests"] += 1

        response = requests.post(
            self.API_URL,
            headers=headers,
            json=data,
            timeout=self.timeout,
        )

        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            return content
        else:
            logger.error(f"OpenRouter API error: {response.status_code} - {response.text}")
            return None

    def _parse_response(
        self,
        response: str,
        alert_name: str,
        latency_ms: float,
    ) -> Optional[AIPlaybook]:
        """Parse AI response into AIPlaybook."""
        try:
            # Extract JSON from response (might be wrapped in markdown)
            json_match = re.search(r'\{[\s\S]*\}', response)
            if not json_match:
                logger.warning("No JSON found in AI response")
                return None

            data = json.loads(json_match.group())

            return AIPlaybook(
                alert_name=alert_name,
                mitre_id=data.get("mitre_id", "Unknown"),
                mitre_name=data.get("mitre_name", "Unknown Technique"),
                severity=data.get("severity", "medium"),
                steps=data.get("steps", []),
                ovs_commands=data.get("ovs_commands", []),
                dns_blocks=data.get("dns_blocks", []),
                owner_narrative=data.get("owner_narrative", "A security event was detected."),
                technical_summary=data.get("technical_summary", response[:200]),
                confidence=0.7,  # AI-generated confidence
                model_used=self.model,
                generation_time_ms=latency_ms,
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            **self._stats,
            "cache_size": len(self._cache),
            "model": self.model,
            "api_configured": bool(self.api_key),
        }


# Singleton instance
_client: Optional[OpenRouterClient] = None


def get_openrouter_client() -> OpenRouterClient:
    """Get or create the singleton OpenRouter client."""
    global _client

    if _client is None:
        _client = OpenRouterClient()

    return _client


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    client = OpenRouterClient()

    print("OpenRouter AI Client")
    print(f"Model: {client.model}")
    print(f"API Configured: {bool(client.api_key)}")

    if client.api_key:
        print("\nGenerating playbook for test alert...")
        playbook = client.generate_playbook(
            alert_name="STUN Tunneling Detected",
            device_type="Employee laptop",
            src_ip="10.200.0.50",
            dst_ip="185.220.101.1",
            dst_port=3478,
        )

        if playbook:
            print(f"\nMITRE: {playbook.mitre_id} - {playbook.mitre_name}")
            print(f"Severity: {playbook.severity}")
            print(f"\nOwner Narrative:\n{playbook.owner_narrative}")
            print(f"\nOVS Commands:")
            for cmd in playbook.ovs_commands:
                print(f"  {cmd}")
        else:
            print("Playbook generation failed")
    else:
        print("\nNo API key - set OPENROUTER_API_KEY environment variable")
