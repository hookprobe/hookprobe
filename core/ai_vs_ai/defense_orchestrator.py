"""
Defense Orchestrator

Orchestrates AI consultation for threat defense strategies.
Integrates with n8n workflows to query AI models and coordinate response.

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import json
import time
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import requests

from .models import (
    IoC,
    ThreatPrediction,
    DefenseStrategy,
    DefenseAction,
    ComputeTier,
    AIConsultationRequest,
    AIConsultationResponse,
)


# N8N webhook endpoints
N8N_BASE_URL = "http://localhost:5678"
N8N_WEBHOOK_THREAT = f"{N8N_BASE_URL}/webhook/threat-analysis"
N8N_WEBHOOK_DEFENSE = f"{N8N_BASE_URL}/webhook/defense-strategy"

# Default AI consultation config
DEFAULT_AI_CONFIG = {
    "local": {
        "enabled": True,
        "endpoint": "http://localhost:11434/api/generate",  # Ollama
        "model": "llama2:7b",
        "timeout": 30,
    },
    "openai": {
        "enabled": False,
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "model": "gpt-4-turbo-preview",
        "timeout": 60,
    },
    "anthropic": {
        "enabled": False,
        "endpoint": "https://api.anthropic.com/v1/messages",
        "model": "claude-3-haiku-20240307",
        "timeout": 60,
    },
}

# Defense action mapping based on attack category
DEFAULT_DEFENSE_ACTIONS = {
    "port_scan": [DefenseAction.RATE_LIMIT, DefenseAction.ALERT],
    "address_scan": [DefenseAction.RATE_LIMIT, DefenseAction.ALERT],
    "syn_flood": [DefenseAction.BLOCK_IP, DefenseAction.RATE_LIMIT],
    "udp_flood": [DefenseAction.BLOCK_IP, DefenseAction.RATE_LIMIT],
    "icmp_flood": [DefenseAction.RATE_LIMIT],
    "brute_force": [DefenseAction.BLOCK_IP, DefenseAction.ALERT],
    "sql_injection": [DefenseAction.BLOCK_IP, DefenseAction.TERMINATE_SESSION, DefenseAction.ALERT],
    "xss": [DefenseAction.TERMINATE_SESSION, DefenseAction.ALERT],
    "dns_tunneling": [DefenseAction.BLOCK_DOMAIN, DefenseAction.ALERT],
    "malware_c2": [DefenseAction.ISOLATE, DefenseAction.BLOCK_IP, DefenseAction.ESCALATE],
    "data_exfiltration": [DefenseAction.ISOLATE, DefenseAction.BLOCK_IP, DefenseAction.ESCALATE],
    "privilege_escalation": [DefenseAction.TERMINATE_SESSION, DefenseAction.ALERT, DefenseAction.ESCALATE],
    "lateral_movement": [DefenseAction.ISOLATE, DefenseAction.ALERT],
    "dos_attack": [DefenseAction.BLOCK_IP, DefenseAction.RATE_LIMIT],
    "reconnaissance": [DefenseAction.ALERT],
    "unknown": [DefenseAction.ALERT],
}


class DefenseOrchestrator:
    """
    Orchestrate AI-based defense strategy generation.

    Flow:
    1. Receive IoC from threat detection
    2. Generate consultation prompt
    3. Query AI model(s) for analysis
    4. Parse response into DefenseStrategy
    5. Trigger n8n workflow for execution
    """

    def __init__(
        self,
        ai_config: Optional[Dict] = None,
        n8n_url: Optional[str] = None,
        compute_tier: ComputeTier = ComputeTier.FORTRESS_LITE
    ):
        self.ai_config = ai_config or DEFAULT_AI_CONFIG.copy()
        self.n8n_url = n8n_url or N8N_BASE_URL
        self.compute_tier = compute_tier

        # Response callbacks
        self._response_callbacks: List[Callable] = []

        # Strategy cache
        self._strategy_cache: Dict[str, DefenseStrategy] = {}

        # Executor for async AI queries
        self._executor = ThreadPoolExecutor(max_workers=3)

        # Statistics
        self._consultation_count = 0
        self._successful_consultations = 0
        self._total_latency_ms = 0

    def consult(
        self,
        ioc: IoC,
        prediction: Optional[ThreatPrediction] = None,
        use_ai: bool = True
    ) -> DefenseStrategy:
        """
        Consult AI for defense strategy.

        Args:
            ioc: Indicator of Compromise to analyze
            prediction: Optional LSTM prediction for context
            use_ai: Whether to actually query AI (False = use defaults)

        Returns:
            DefenseStrategy with recommended actions
        """
        start_time = time.time()
        self._consultation_count += 1

        # Check cache
        cache_key = self._cache_key(ioc)
        if cache_key in self._strategy_cache:
            cached = self._strategy_cache[cache_key]
            # Return cached if less than 5 minutes old
            cache_age = (datetime.now() - datetime.fromisoformat(cached.timestamp)).seconds
            if cache_age < 300:
                return cached

        # Build consultation request
        request = AIConsultationRequest(
            ioc=ioc,
            prediction=prediction,
            context={
                "compute_tier": self.compute_tier.value,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Get strategy
        if use_ai and self.compute_tier != ComputeTier.FORTRESS_LITE:
            strategy = self._ai_consultation(request)
        else:
            strategy = self._default_strategy(ioc)

        # Cache result
        self._strategy_cache[cache_key] = strategy

        # Track performance
        latency_ms = (time.time() - start_time) * 1000
        self._total_latency_ms += latency_ms

        # Notify callbacks
        for callback in self._response_callbacks:
            try:
                callback(strategy)
            except Exception as e:
                print(f"Callback error: {e}")

        return strategy

    def _ai_consultation(self, request: AIConsultationRequest) -> DefenseStrategy:
        """Query AI model for strategy"""
        # Try each configured AI in order
        for ai_name, config in self.ai_config.items():
            if not config.get("enabled", False):
                continue

            try:
                response = self._query_ai(ai_name, config, request)
                if response.success:
                    self._successful_consultations += 1
                    return self._parse_ai_response(request, response)
            except Exception as e:
                print(f"AI consultation error ({ai_name}): {e}")
                continue

        # Fall back to default strategy
        print("All AI consultations failed, using default strategy")
        return self._default_strategy(request.ioc)

    def _query_ai(
        self,
        ai_name: str,
        config: Dict,
        request: AIConsultationRequest
    ) -> AIConsultationResponse:
        """Query specific AI endpoint"""
        start_time = time.time()

        if ai_name == "local":
            response = self._query_ollama(config, request)
        elif ai_name == "openai":
            response = self._query_openai(config, request)
        elif ai_name == "anthropic":
            response = self._query_anthropic(config, request)
        else:
            raise ValueError(f"Unknown AI: {ai_name}")

        response.latency_ms = int((time.time() - start_time) * 1000)
        response.model_used = f"{ai_name}:{config.get('model', 'unknown')}"

        return response

    def _query_ollama(
        self,
        config: Dict,
        request: AIConsultationRequest
    ) -> AIConsultationResponse:
        """Query local Ollama model"""
        try:
            payload = {
                "model": config.get("model", "llama2:7b"),
                "prompt": request.prompt,
                "stream": False,
                "options": {
                    "temperature": request.temperature,
                    "num_predict": request.max_tokens,
                }
            }

            resp = requests.post(
                config["endpoint"],
                json=payload,
                timeout=config.get("timeout", 30)
            )
            resp.raise_for_status()

            data = resp.json()

            return AIConsultationResponse(
                request_id=request.request_id,
                raw_response=data.get("response", ""),
                tokens_used=data.get("eval_count", 0),
                success=True,
            )

        except Exception as e:
            return AIConsultationResponse(
                request_id=request.request_id,
                success=False,
                error_message=str(e),
            )

    def _query_openai(
        self,
        config: Dict,
        request: AIConsultationRequest
    ) -> AIConsultationResponse:
        """Query OpenAI API"""
        try:
            import os
            api_key = os.environ.get("OPENAI_API_KEY", "")

            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": config.get("model", "gpt-4-turbo-preview"),
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity defense AI. Analyze threats and recommend defense strategies."
                    },
                    {
                        "role": "user",
                        "content": request.prompt
                    }
                ],
                "temperature": request.temperature,
                "max_tokens": request.max_tokens,
            }

            resp = requests.post(
                config["endpoint"],
                headers=headers,
                json=payload,
                timeout=config.get("timeout", 60)
            )
            resp.raise_for_status()

            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            return AIConsultationResponse(
                request_id=request.request_id,
                raw_response=content,
                tokens_used=data.get("usage", {}).get("total_tokens", 0),
                success=True,
            )

        except Exception as e:
            return AIConsultationResponse(
                request_id=request.request_id,
                success=False,
                error_message=str(e),
            )

    def _query_anthropic(
        self,
        config: Dict,
        request: AIConsultationRequest
    ) -> AIConsultationResponse:
        """Query Anthropic API"""
        try:
            import os
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")

            headers = {
                "x-api-key": api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            }

            payload = {
                "model": config.get("model", "claude-3-haiku-20240307"),
                "messages": [
                    {
                        "role": "user",
                        "content": request.prompt
                    }
                ],
                "max_tokens": request.max_tokens,
            }

            resp = requests.post(
                config["endpoint"],
                headers=headers,
                json=payload,
                timeout=config.get("timeout", 60)
            )
            resp.raise_for_status()

            data = resp.json()
            content = data["content"][0]["text"]

            return AIConsultationResponse(
                request_id=request.request_id,
                raw_response=content,
                tokens_used=data.get("usage", {}).get("input_tokens", 0) +
                           data.get("usage", {}).get("output_tokens", 0),
                success=True,
            )

        except Exception as e:
            return AIConsultationResponse(
                request_id=request.request_id,
                success=False,
                error_message=str(e),
            )

    def _parse_ai_response(
        self,
        request: AIConsultationRequest,
        response: AIConsultationResponse
    ) -> DefenseStrategy:
        """Parse AI response into DefenseStrategy"""
        raw = response.raw_response.lower()
        ioc = request.ioc

        # Extract recommended actions from response
        actions = []

        # Pattern matching for common recommendations
        action_patterns = {
            DefenseAction.BLOCK_IP: ["block ip", "block the ip", "firewall", "blacklist"],
            DefenseAction.RATE_LIMIT: ["rate limit", "throttle", "limit rate"],
            DefenseAction.QUARANTINE: ["quarantine", "isolate device", "sandbox"],
            DefenseAction.ISOLATE: ["isolate", "network isolation", "segment"],
            DefenseAction.ALERT: ["alert", "notify", "warning", "monitor"],
            DefenseAction.TERMINATE_SESSION: ["terminate", "kill session", "disconnect"],
            DefenseAction.HONEYPOT_REDIRECT: ["honeypot", "decoy", "trap"],
            DefenseAction.ESCALATE: ["escalate", "security team", "soc"],
            DefenseAction.UPDATE_RULES: ["update rule", "add rule", "modify rule"],
            DefenseAction.RETRAIN_MODEL: ["retrain", "update model", "improve detection"],
        }

        for action, patterns in action_patterns.items():
            if any(p in raw for p in patterns):
                actions.append(action)

        # Ensure at least one action
        if not actions:
            actions = DEFAULT_DEFENSE_ACTIONS.get(
                ioc.attack_category, [DefenseAction.ALERT]
            )

        # Extract confidence from response
        confidence = 0.7  # Default
        if "high confidence" in raw or "definitely" in raw:
            confidence = 0.9
        elif "low confidence" in raw or "uncertain" in raw:
            confidence = 0.5

        # Extract reasoning
        reasoning = response.raw_response[:500]  # First 500 chars

        # Build strategy
        primary_action = actions[0] if actions else DefenseAction.ALERT
        secondary_actions = actions[1:] if len(actions) > 1 else []

        return DefenseStrategy(
            ioc_id=ioc.ioc_id,
            primary_action=primary_action,
            secondary_actions=secondary_actions,
            action_params=self._build_action_params(ioc, actions),
            reasoning=reasoning,
            confidence=confidence,
            risk_assessment=f"Severity: {ioc.severity.value}, Confidence: {ioc.confidence:.0%}",
            expected_effectiveness=0.8 if confidence > 0.7 else 0.6,
            compute_tier_required=self.compute_tier,
            monitoring_recommendations=self._extract_monitoring_recs(raw),
            model_update_suggestions=self._extract_model_suggestions(raw),
        )

    def _default_strategy(self, ioc: IoC) -> DefenseStrategy:
        """Generate default strategy without AI"""
        actions = DEFAULT_DEFENSE_ACTIONS.get(
            ioc.attack_category, [DefenseAction.ALERT]
        )

        return DefenseStrategy(
            ioc_id=ioc.ioc_id,
            primary_action=actions[0],
            secondary_actions=actions[1:] if len(actions) > 1 else [],
            action_params=self._build_action_params(ioc, actions),
            reasoning=f"Default response for {ioc.attack_category}",
            confidence=0.6,
            risk_assessment=f"Severity: {ioc.severity.value}",
            expected_effectiveness=0.7,
            compute_tier_required=ComputeTier.FORTRESS_LITE,
        )

    def _build_action_params(
        self,
        ioc: IoC,
        actions: List[DefenseAction]
    ) -> Dict[str, Any]:
        """Build parameters for defense actions"""
        params = {}

        for action in actions:
            if action == DefenseAction.BLOCK_IP:
                params["block_ip"] = {
                    "duration_minutes": 60 if ioc.severity.value in ["critical", "high"] else 15,
                    "source": ioc.source_system,
                }
            elif action == DefenseAction.RATE_LIMIT:
                params["rate_limit"] = {
                    "requests_per_minute": 10 if ioc.severity.value == "critical" else 30,
                }
            elif action == DefenseAction.BLOCK_DOMAIN:
                params["block_domain"] = {
                    "duration_minutes": 1440,  # 24 hours
                }

        return params

    def _extract_monitoring_recs(self, response: str) -> List[str]:
        """Extract monitoring recommendations from AI response"""
        recs = []
        if "monitor" in response:
            recs.append("Continue monitoring for similar patterns")
        if "watch" in response or "observe" in response:
            recs.append("Observe for follow-up attacks")
        if "log" in response:
            recs.append("Enable enhanced logging")
        return recs[:3]

    def _extract_model_suggestions(self, response: str) -> List[str]:
        """Extract model update suggestions from AI response"""
        suggestions = []
        if "false positive" in response:
            suggestions.append("Review for potential false positive")
        if "retrain" in response or "update model" in response:
            suggestions.append("Consider retraining with this example")
        if "new pattern" in response or "unknown" in response:
            suggestions.append("Add to anomaly detection training set")
        return suggestions[:3]

    def _cache_key(self, ioc: IoC) -> str:
        """Generate cache key for IoC"""
        return hashlib.md5(
            f"{ioc.ioc_type.value}:{ioc.value}:{ioc.attack_category}".encode()
        ).hexdigest()[:16]

    def trigger_n8n_workflow(
        self,
        strategy: DefenseStrategy,
        ioc: IoC
    ) -> bool:
        """
        Trigger n8n workflow for defense execution.

        Args:
            strategy: Defense strategy to execute
            ioc: Original IoC

        Returns:
            True if workflow triggered successfully
        """
        try:
            payload = {
                "ioc": ioc.to_dict(),
                "strategy": strategy.to_dict(),
                "timestamp": datetime.now().isoformat(),
            }

            resp = requests.post(
                f"{self.n8n_url}/webhook/defense-execute",
                json=payload,
                timeout=10
            )

            return resp.status_code == 200

        except Exception as e:
            print(f"n8n trigger error: {e}")
            return False

    def register_callback(self, callback: Callable[[DefenseStrategy], None]):
        """Register callback for strategy responses"""
        self._response_callbacks.append(callback)

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        avg_latency = (
            self._total_latency_ms / self._consultation_count
            if self._consultation_count > 0 else 0
        )
        success_rate = (
            self._successful_consultations / self._consultation_count
            if self._consultation_count > 0 else 0
        )

        return {
            "consultation_count": self._consultation_count,
            "successful_consultations": self._successful_consultations,
            "success_rate": success_rate,
            "avg_latency_ms": avg_latency,
            "cache_size": len(self._strategy_cache),
            "compute_tier": self.compute_tier.value,
            "enabled_ais": [
                name for name, cfg in self.ai_config.items()
                if cfg.get("enabled", False)
            ],
        }


def create_orchestrator_for_tier(
    tier: ComputeTier,
    enable_local_ai: bool = True
) -> DefenseOrchestrator:
    """
    Factory function to create orchestrator for compute tier.

    Args:
        tier: Target compute tier
        enable_local_ai: Whether to enable local Ollama AI

    Returns:
        Configured DefenseOrchestrator
    """
    config = DEFAULT_AI_CONFIG.copy()
    config["local"]["enabled"] = enable_local_ai

    # Enable cloud AI only for higher tiers
    if tier in [ComputeTier.NEXUS_ADVANCED, ComputeTier.MSSP_CLOUD]:
        config["openai"]["enabled"] = True
        config["anthropic"]["enabled"] = True

    return DefenseOrchestrator(ai_config=config, compute_tier=tier)
