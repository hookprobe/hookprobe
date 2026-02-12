"""
AEGIS Type Definitions

Pydantic models for structured LLM output and API contracts.
"""

from datetime import datetime
from typing import List, Optional
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
