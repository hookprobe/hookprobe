"""
AEGIS Neuro-Kernel — LLM-Driven Kernel Orchestration

Phase 1: Template-based eBPF deployment via AEGIS orchestrator.
Known patterns auto-deploy verified eBPF filters at NIC level.

Phase 2: Streaming eBPF-RAG — real-time vector-embedded kernel events
for LLM situational awareness.

Architecture layers (phased rollout):
  Layer 1: Closed-Loop Kernel Orchestrator (Phase 1)
  Layer 2: Streaming eBPF-RAG (Phase 2)
  Layer 3: Shadow Pentester (Phase 4)
  Layer 4: Hybrid Inference (Phase 5)

Author: Andrei Toma
License: Proprietary
Version: 2.0.0
"""

from typing import Optional

# Phase 1: Kernel Orchestration
from .kernel_orchestrator import KernelOrchestrator
from .ebpf_compiler import EBPFCompiler
from .ebpf_sandbox import EBPFSandbox
from .ebpf_template_registry import TemplateRegistry
from .ebpf_verifier_wrapper import EBPFVerifier
from .sensor_manager import SensorManager

# Phase 2: Streaming eBPF-RAG
from .event_chunker import EventChunk, EventChunker
from .embedding_engine import EmbeddingEngine, cosine_similarity
from .vector_store import VectorStore, SQLiteVectorStore, create_vector_store
from .streaming_rag import StreamingRAGPipeline

from .types import (
    ActiveProgram,
    CompilationResult,
    KernelAction,
    KernelActionType,
    ProgramType,
    SandboxResult,
    SandboxTestResult,
    SensorEvent,
    SensorType,
    TemplateMatch,
    VerifyStatus,
)

# ------------------------------------------------------------------
# Singleton registry (same pattern as reflex/__init__.py)
# ------------------------------------------------------------------

_orchestrator_instance: Optional[KernelOrchestrator] = None


def register_orchestrator(orch: KernelOrchestrator) -> None:
    """Register the global KernelOrchestrator instance."""
    global _orchestrator_instance
    _orchestrator_instance = orch


def get_orchestrator() -> Optional[KernelOrchestrator]:
    """Get the registered KernelOrchestrator, or None."""
    return _orchestrator_instance


__all__ = [
    # Phase 1: Kernel Orchestration
    "KernelOrchestrator",
    "EBPFCompiler",
    "EBPFSandbox",
    "EBPFVerifier",
    "TemplateRegistry",
    "SensorManager",
    # Phase 2: Streaming eBPF-RAG
    "EventChunk",
    "EventChunker",
    "EmbeddingEngine",
    "cosine_similarity",
    "VectorStore",
    "SQLiteVectorStore",
    "create_vector_store",
    "StreamingRAGPipeline",
    # Types
    "ActiveProgram",
    "CompilationResult",
    "KernelAction",
    "KernelActionType",
    "ProgramType",
    "SandboxResult",
    "SandboxTestResult",
    "SensorEvent",
    "SensorType",
    "TemplateMatch",
    "VerifyStatus",
    # Registry
    "register_orchestrator",
    "get_orchestrator",
]
