"""
AEGIS Content Scribe Agent — Incident-to-Content Pipeline

Transforms security events into blog drafts, video scripts, and social
media posts. Feeds the SEO Brain pipeline with technically accurate,
RAG-grounded content from real security operations.

Triggers:
- incident.resolved (post-mortem generation)
- cve.new (CVE analysis blog draft)
- threat.campaign (threat landscape report)
- manual.content_request (ad-hoc content)
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .base import BaseAgent
from ..types import AgentResponse, StandardSignal

if TYPE_CHECKING:
    from ..inference import NativeInferenceEngine
    from ..memory import MemoryManager
    from ..signal_fabric import SignalFabric
    from ..soul import SoulConfig

logger = logging.getLogger(__name__)


class ScribeAgent(BaseAgent):
    """Content Scribe — converts security events into SEO-optimized content."""

    name = "SCRIBE"
    description = (
        "Content generation agent. Transforms security incidents, CVE analyses, "
        "and threat campaigns into blog posts, video scripts, and social media content. "
        "Uses RAG context from the HookProbe knowledge base for technical accuracy."
    )

    trigger_patterns = [
        r"incident\.resolved",
        r"incident\.postmortem",
        r"cve\.new",
        r"cve\.analysis",
        r"threat\.campaign",
        r"threat\.landscape",
        r"content\.request",
        r"content\.generate",
    ]

    allowed_tools = [
        "rag_search",         # Search pgvector knowledge base
        "blog_create_draft",  # Create blog post draft
        "social_queue",       # Queue social media post
        "clickhouse_query",   # Query threat statistics
    ]

    confidence_threshold = 0.5  # Lower threshold — content is always reviewed

    def respond(
        self,
        signal: Optional[StandardSignal] = None,
        query: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResponse:
        """Generate content from a security event or query."""
        start = time.monotonic()

        if signal:
            return self._handle_signal(signal, context or {})
        elif query:
            return self._handle_query(query, context or {})
        else:
            return AgentResponse(
                agent=self.name,
                content="No signal or query provided.",
                confidence=0.0,
                actions=[],
            )

    def _handle_signal(self, signal: StandardSignal, context: Dict) -> AgentResponse:
        """Process a security signal and generate content."""
        event_type = signal.type if hasattr(signal, 'type') else str(signal)

        # Determine content type from signal
        if "incident" in event_type:
            return self._generate_post_mortem(signal, context)
        elif "cve" in event_type:
            return self._generate_cve_analysis(signal, context)
        elif "campaign" in event_type or "landscape" in event_type:
            return self._generate_threat_report(signal, context)
        else:
            return self._generate_generic(signal, context)

    def _handle_query(self, query: str, context: Dict) -> AgentResponse:
        """Handle a direct content request."""
        # Use inference engine to generate content
        prompt = f"""You are a cybersecurity content writer for HookProbe.
Generate a technical blog post outline for: {query}

Include:
- SEO-optimized title (50-60 chars)
- 3-5 key points to cover
- Technical depth appropriate for security professionals
- Where HookProbe's capabilities are relevant

Return a brief outline, not the full article."""

        try:
            response = self.engine.infer(prompt, max_tokens=500)
            return AgentResponse(
                agent=self.name,
                content=response,
                confidence=0.7,
                actions=[{"type": "content_outline", "query": query}],
            )
        except Exception as e:
            logger.error(f"Scribe inference failed: {e}")
            return AgentResponse(
                agent=self.name,
                content=f"Content generation failed: {e}",
                confidence=0.0,
                actions=[],
            )

    def _generate_post_mortem(self, signal: StandardSignal, context: Dict) -> AgentResponse:
        """Generate a post-mortem blog draft from a resolved incident."""
        payload = signal.payload if hasattr(signal, 'payload') else {}

        prompt = f"""Write a concise post-mortem summary for a security incident.

Incident details: {json.dumps(payload, default=str)[:1000]}

Format as:
1. What happened (2-3 sentences)
2. How HookProbe detected it (which engine: HYDRA, NAPSE, XDP)
3. Response timeline
4. Lessons learned
5. Suggested blog title (SEO-optimized)

Keep it factual and technical."""

        try:
            response = self.engine.infer(prompt, max_tokens=800)
            return AgentResponse(
                agent=self.name,
                content=response,
                confidence=0.6,
                actions=[
                    {"type": "blog_draft", "source": "post_mortem"},
                    {"type": "social_queue", "platform": "linkedin"},
                ],
                metadata={"content_type": "post_mortem", "signal_type": str(signal)},
            )
        except Exception as e:
            logger.error(f"Post-mortem generation failed: {e}")
            return AgentResponse(
                agent=self.name,
                content=f"Post-mortem failed: {e}",
                confidence=0.0,
                actions=[],
            )

    def _generate_cve_analysis(self, signal: StandardSignal, context: Dict) -> AgentResponse:
        """Generate a CVE analysis blog draft."""
        payload = signal.payload if hasattr(signal, 'payload') else {}
        cve_id = payload.get("cve_id", "unknown")

        prompt = f"""Write a brief CVE analysis for {cve_id}.

CVE details: {json.dumps(payload, default=str)[:800]}

Include:
1. Vulnerability description
2. Affected systems/software
3. How HookProbe detects/prevents this
4. Recommended mitigation steps
5. SEO-optimized title

Keep technical but accessible."""

        try:
            response = self.engine.infer(prompt, max_tokens=800)
            return AgentResponse(
                agent=self.name,
                content=response,
                confidence=0.6,
                actions=[{"type": "blog_draft", "source": "cve_analysis", "cve_id": cve_id}],
                metadata={"content_type": "cve_analysis", "cve_id": cve_id},
            )
        except Exception as e:
            return AgentResponse(
                agent=self.name,
                content=f"CVE analysis failed: {e}",
                confidence=0.0,
                actions=[],
            )

    def _generate_threat_report(self, signal: StandardSignal, context: Dict) -> AgentResponse:
        """Generate a threat landscape report."""
        return AgentResponse(
            agent=self.name,
            content="Threat landscape report generation queued.",
            confidence=0.5,
            actions=[{"type": "report_draft", "source": "threat_landscape"}],
            metadata={"content_type": "threat_report"},
        )

    def _generate_generic(self, signal: StandardSignal, context: Dict) -> AgentResponse:
        """Handle generic content requests."""
        return AgentResponse(
            agent=self.name,
            content=f"Content generation queued for signal: {signal}",
            confidence=0.4,
            actions=[{"type": "content_queue"}],
        )
