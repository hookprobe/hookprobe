"""
AEGIS Type Definitions

Pydantic models for structured LLM output and API contracts.
Dataclasses for internal types that don't need Pydantic validation.
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """A single conversation message."""
    role: str = Field(description="Message role: user, assistant, or system")
    content: str = Field(description="Message text content")
    timestamp: datetime = Field(default_factory=datetime.now)


class ChatResponse(BaseModel):
    """Response from the AEGIS agent."""
    message: str = Field(description="Response text")
    agent: str = Field(default="ORACLE", description="Agent that generated the response")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Response confidence")
    sources: List[str] = Field(default_factory=list, description="Data sources used")


class AegisStatus(BaseModel):
    """AEGIS system health status."""
    llm_ready: bool = Field(default=False, description="Whether the LLM is loaded and ready")
    model_loaded: bool = Field(default=False, description="Whether the LLM model is loaded")
    model_name: str = Field(default="", description="Active model name")
    uptime: float = Field(default=0.0, description="Agent uptime in seconds")
    tier: str = Field(default="template", description="Intelligence tier: template, cloud")
    loading: bool = Field(default=False, description="Whether a model is currently loading")
    load_error: str = Field(default="", description="Last model load error message")
    ram_usage_mb: float = Field(default=0.0, description="Process RAM usage in MB")
    avg_inference_ms: float = Field(default=0.0, description="Average inference latency in ms")
    enabled: bool = Field(default=True, description="Whether AEGIS is enabled")


class NetworkSummary(BaseModel):
    """Aggregated network status for LLM context."""
    qsecbit_score: float = Field(default=0.85, description="QSecBit score (0.0-1.0)")
    qsecbit_status: str = Field(default="GREEN", description="RAG status")
    device_count: int = Field(default=0, description="Connected device count")
    threat_count: int = Field(default=0, description="Active threats in last 24h")
    dns_blocked_24h: int = Field(default=0, description="DNS queries blocked in 24h")
    wan_status: str = Field(default="online", description="WAN connection status")
    wan_primary_health: int = Field(default=95, description="Primary WAN health %")


class ThreatSummary(BaseModel):
    """Individual threat detail for LLM context."""
    type: str = Field(description="Threat type (e.g., ARP_SPOOF, PORT_SCAN)")
    severity: str = Field(default="LOW", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    target: Optional[str] = Field(default=None, description="Target device or service")
    description: str = Field(default="", description="Human-readable description")
    recommendation: str = Field(default="", description="Recommended action")


class DeviceInfo(BaseModel):
    """Device information for LLM context."""
    mac: str = Field(description="MAC address")
    ip: Optional[str] = Field(default=None, description="IP address")
    hostname: Optional[str] = Field(default=None, description="Device hostname")
    vendor: Optional[str] = Field(default=None, description="Hardware vendor (OUI)")
    device_type: Optional[str] = Field(default=None, description="Classified device type")
    bubble: Optional[str] = Field(default=None, description="Ecosystem bubble name")
    first_seen: Optional[str] = Field(default=None, description="First seen timestamp")
    last_seen: Optional[str] = Field(default=None, description="Last seen timestamp")


# ------------------------------------------------------------------
# Signal Types (used by bridges and orchestrator)
# ------------------------------------------------------------------

class SignalSeverity(str, Enum):
    """Signal severity levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class StandardSignal:
    """Normalized signal from any bridge.

    All signal bridges normalize their events to this format
    before feeding them to the orchestrator.
    """
    source: str          # "qsecbit", "dnsxai", "dhcp", etc.
    event_type: str      # "threat", "dns_block", "new_device", etc.
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    timestamp: datetime = dc_field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = dc_field(default_factory=dict)

    @property
    def is_threat(self) -> bool:
        return self.severity in ("HIGH", "CRITICAL") or "threat" in self.event_type


# ------------------------------------------------------------------
# Agent Types (used by agents and orchestrator)
# ------------------------------------------------------------------

@dataclass
class AgentInvocation:
    """Record of an agent being invoked for a signal."""
    agent_name: str
    signal: Optional[StandardSignal] = None
    timestamp: datetime = dc_field(default_factory=datetime.utcnow)
    user_query: str = ""


@dataclass
class AgentResponse:
    """Response from an agent after processing a signal or query."""
    agent: str
    action: str = ""           # Tool/action name, empty if advisory only
    confidence: float = 0.0
    reasoning: str = ""        # Why this action was chosen
    user_message: str = ""     # Human-readable response
    tool_calls: List[Dict[str, Any]] = dc_field(default_factory=list)
    sources: List[str] = dc_field(default_factory=list)
    escalate_to: Optional[str] = None  # Agent name to escalate to


# ------------------------------------------------------------------
# Tool Types (used by tool_executor)
# ------------------------------------------------------------------

@dataclass
class ToolDefinition:
    """Definition of a tool available to agents."""
    name: str
    description: str
    parameters: Dict[str, Any] = dc_field(default_factory=dict)  # JSON Schema
    agents: List[str] = dc_field(default_factory=list)  # Which agents can use this
    requires_confirmation: bool = False


@dataclass
class ToolResult:
    """Result of executing a tool."""
    success: bool
    result: str = ""
    reasoning: str = ""
    logged: bool = False
    decision_id: str = ""
