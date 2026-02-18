# Neuro-Kernel Architecture: LLM-Driven Kernel Orchestration

**Version**: 1.0.0
**Author**: Security Architect
**Date**: 2026-02-18
**Status**: Architecture Proposal

---

## 1. Problem Statement

HookProbe's current defense pipeline is reactive: NAPSE detects threats, QSecBit scores
them, Reflex applies graduated interference, and AEGIS agents reason about events. This
works well for known threats, but zero-day attacks exploit the gap between detection and
response. The Neuro-Kernel closes this gap by:

1. Giving the LLM direct read access to kernel telemetry (eBPF sensors)
2. Allowing the LLM to generate and deploy new eBPF filters in response to novel patterns
3. Providing streaming situational awareness via vector-embedded kernel events
4. Running continuous adversarial testing against a digital twin

The core insight: **the Linux kernel becomes both the sensory system and the immune system,
with the LLM as the cognitive layer between them**.

---

## 2. Constraints and Assumptions

### Hardware Constraints (Product Tiers)

| Tier       | RAM     | CPU       | Neuro-Kernel Capability                     |
|------------|---------|-----------|---------------------------------------------|
| Sentinel   | 256MB   | 1-2 core  | Receive-only: deploy pre-built eBPF filters |
| Guardian   | 1.5GB   | 4 core    | Fast-path QSecBit + edge offload to Nexus   |
| Fortress   | 4GB     | 4 core    | Local 0.5-3B model + streaming RAG (128MB)  |
| Nexus      | 16GB+   | 8+ core   | Full 8B model + vector DB + shadow pentester|

### Security Constraints

- LLM-generated eBPF code MUST pass the kernel verifier (non-negotiable)
- LLM-generated code MUST be sandboxed and reviewed before deployment
- Principle Guard MUST gate all kernel-modifying actions
- The LLM itself MUST be monitored for compromise (eBPF uprobes on inference)
- No shell=True, no eval(), no dynamic code execution outside the eBPF sandbox

### Existing Integration Points

| Component              | File                                          | Integration Method        |
|------------------------|-----------------------------------------------|---------------------------|
| AEGIS Orchestrator     | `core/aegis/orchestrator.py`                  | New routing rules         |
| AEGIS Inference        | `core/aegis/inference.py`                     | Extended with vLLM backend|
| AEGIS Tool Executor    | `core/aegis/tool_executor.py`                 | New kernel tools          |
| AEGIS Principle Guard  | `core/aegis/principle_guard.py`               | New kernel principles     |
| AEGIS Memory           | `core/aegis/memory.py`                        | New vector layer          |
| Reflex Engine          | `core/aegis/reflex/engine.py`                 | Hot-swap hook             |
| Reflex eBPF Programs   | `core/aegis/reflex/ebpf_programs.py`          | Template registry         |
| NAPSE Bridge           | `core/aegis/bridges/napse_bridge.py`          | Event enrichment          |
| QSecBit XDP Manager    | `core/qsecbit/xdp_manager.py`                | Coordinated loading       |
| Digital Twin           | `products/nexus/lib/red_purple_teaming/digital_twin.py` | Extended    |
| Purple Team Orch.      | `products/nexus/lib/red_purple_teaming/orchestrator.py` | Extended    |
| Unified Transport      | `shared/mesh/unified_transport.py`            | New KERNEL_EVENT packet   |
| AEGIS Profiles         | `core/aegis/profiles/{pico,lite,full,deep}.py`| Tier-appropriate config   |
| Virtual Sandbox        | `core/aegis/tools/virtual_sandbox.py`         | Twin integration          |

---

## 3. Architecture Overview

```
                         NEURO-KERNEL ARCHITECTURE
 ============================================================================

    LAYER 4: HYBRID INFERENCE (Edge + Nexus)
    ┌──────────────────────────────────────────────────────────────────────┐
    │                                                                      │
    │  EDGE (Sentinel/Guardian/Fortress)     NEXUS (16GB+)                │
    │  ┌──────────────────────┐             ┌──────────────────────────┐  │
    │  │ QSecBit Fast Path    │   offload   │ 8B LLM (vLLM/Ollama)    │  │
    │  │ (0.5B model or rules)│ ──────────▶ │ Complex reasoning        │  │
    │  │ 99% known threats    │   eBPF      │ eBPF code generation    │  │
    │  │                      │   trace     │ Verdict: Allow/Drop/Inv  │  │
    │  └──────────────────────┘             └──────────────────────────┘  │
    │                                                                      │
    │  LLM SELF-MONITOR (eBPF Uprobes)                                   │
    │  ┌──────────────────────────────────────────────────────────────┐   │
    │  │ Monitor Ollama/vLLM process: syscalls, memory, outputs      │   │
    │  │ If malicious code generation detected -> kernel kills LLM   │   │
    │  └──────────────────────────────────────────────────────────────┘   │
    └──────────────────────────────────────────────────────────────────────┘

    LAYER 3: SHADOW PENTESTER (Continuous Offensive Testing)
    ┌──────────────────────────────────────────────────────────────────────┐
    │                                                                      │
    │  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐           │
    │  │ DIGITAL TWIN│────▶│ OFFENSIVE   │────▶│ DEFENSIVE   │           │
    │  │ (Nexus VM)  │     │ LLM AGENT   │     │ FEEDBACK    │           │
    │  │             │     │ (Red Team)   │     │ (Blue Team) │           │
    │  └─────────────┘     └─────────────┘     └─────────────┘           │
    │   Network clone       Finds vulns         Updates QSecBit           │
    │   eBPF replay         Tests defenses      Generates new eBPF       │
    │                                                                      │
    └──────────────────────────────────────────────────────────────────────┘

    LAYER 2: STREAMING eBPF-RAG (Real-Time Context)
    ┌──────────────────────────────────────────────────────────────────────┐
    │                                                                      │
    │  eBPF Sensors ──▶ Ring Buffer ──▶ Chunker ──▶ Embedder ──▶ VectorDB│
    │  (syscalls,       (perf_event     (60s        (MiniLM    (ChromaDB  │
    │   packets,         output_buf)     windows)    384-dim)    or SQLite │
    │   file ops)                                                w/ HNSW) │
    │                                                                      │
    │  LLM Query: "What happened in the last 60s on this subnet?"        │
    │       ▼                                                              │
    │  Vector search → top-K chunks → inject as context → LLM reasons    │
    │                                                                      │
    └──────────────────────────────────────────────────────────────────────┘

    LAYER 1: CLOSED-LOOP KERNEL ORCHESTRATOR (Brain-to-Kernel)
    ┌──────────────────────────────────────────────────────────────────────┐
    │                                                                      │
    │  NAPSE eBPF ──▶ AEGIS ──▶ LLM Analyzes ──▶ Generates C ──▶ Verify │
    │  telemetry       Bridge    zero-day           eBPF code     eBPF    │
    │                              pattern                        verifier│
    │                                                     │               │
    │                                              ┌──────▼──────┐        │
    │                                              │ SANDBOX     │        │
    │                                              │ TEST (30s)  │        │
    │                                              └──────┬──────┘        │
    │                                                     │               │
    │                           Reflex Engine ◀───── HOT-SWAP             │
    │                           (existing)         (BPF program)          │
    │                                                                      │
    └──────────────────────────────────────────────────────────────────────┘

    KERNEL LAYER (Linux 5.15+)
    ┌──────────────────────────────────────────────────────────────────────┐
    │  XDP (NIC)  │  TC (qdisc)  │  kprobes  │  tracepoints  │  uprobes │
    │  drop@wire   delay/jitter   syscall     sched/net       LLM monitor│
    └──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Detailed Design: Layer 1 — Closed-Loop Kernel Orchestrator

### 4.1 New Files

```
core/aegis/neurokernel/
    __init__.py
    kernel_orchestrator.py      # Central coordinator
    ebpf_compiler.py            # LLM code → verified eBPF
    ebpf_template_registry.py   # Pre-vetted eBPF templates
    ebpf_sandbox.py             # Isolated test environment
    ebpf_verifier_wrapper.py    # Python wrapper around BPF verifier
    sensor_manager.py           # eBPF sensor lifecycle
    types.py                    # Data types for the system
```

### 4.2 `kernel_orchestrator.py` — Central Coordinator

```python
"""
Neuro-Kernel Orchestrator — Brain-to-Kernel Closed Loop

Receives NAPSE telemetry via AEGIS bridges, detects novel patterns,
invokes the LLM to generate eBPF countermeasures, verifies them,
and hot-swaps into the Reflex engine.

Pipeline:
    NAPSE event → pattern_detector → LLM reasoning → eBPF generation
    → verification → sandbox test → hot-swap → audit

Integration points:
    - Reads from: AEGIS orchestrator (StandardSignal)
    - Writes to: ReflexEngine (hot-swap eBPF programs)
    - Guarded by: PrincipleGuard (never_disable_protection)
    - Audited by: MemoryManager (decisions table)
    - Coordinated with: XDPManager (prevent conflicts)
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..inference import NativeInferenceEngine
from ..memory import MemoryManager
from ..principle_guard import check_action, SafetyCheckResult
from ..reflex.engine import ReflexEngine
from ..types import StandardSignal
from .ebpf_compiler import EBPFCompiler, CompilationResult
from .ebpf_sandbox import EBPFSandbox
from .ebpf_template_registry import TemplateRegistry
from .sensor_manager import SensorManager
from .types import KernelAction, KernelActionType

logger = logging.getLogger(__name__)


class KernelOrchestrator:
    """Closed-loop: NAPSE telemetry -> LLM reasoning -> eBPF response.

    Security invariants:
    1. All generated eBPF passes kernel verifier
    2. All actions gated by PrincipleGuard
    3. Sandbox testing before production deployment
    4. Human approval required for novel (non-template) programs
    5. Automatic rollback on anomalous behavior
    """

    MAX_ACTIVE_PROGRAMS = 32          # Limit concurrent custom eBPF
    SANDBOX_DURATION_S = 30           # Test window before production
    ROLLBACK_TIMEOUT_S = 300          # Auto-rollback if no improvement

    def __init__(
        self,
        inference: NativeInferenceEngine,
        memory: MemoryManager,
        reflex: ReflexEngine,
        compiler: Optional[EBPFCompiler] = None,
        sandbox: Optional[EBPFSandbox] = None,
        sensors: Optional[SensorManager] = None,
    ):
        self._inference = inference
        self._memory = memory
        self._reflex = reflex
        self._compiler = compiler or EBPFCompiler()
        self._sandbox = sandbox or EBPFSandbox()
        self._sensors = sensors or SensorManager()
        self._templates = TemplateRegistry()
        self._active_programs: Dict[str, KernelAction] = {}
        self._lock = threading.Lock()

    def handle_signal(self, signal: StandardSignal) -> Optional[KernelAction]:
        """Process a signal that may require kernel-level response.

        Decision tree:
        1. Is this a known pattern? -> Use template eBPF
        2. Is this novel but matches partial signatures? -> LLM generates
        3. Is confidence too low? -> Offload to Nexus for analysis
        """
        # Step 1: Check template registry for known patterns
        template = self._templates.match(signal)
        if template:
            return self._deploy_template(template, signal)

        # Step 2: Check if LLM reasoning is needed
        if signal.severity in ("HIGH", "CRITICAL"):
            return self._llm_generate_response(signal)

        # Step 3: Offload ambiguous signals to Nexus
        if signal.severity == "MEDIUM":
            self._offload_to_nexus(signal)

        return None

    def _llm_generate_response(self, signal: StandardSignal) -> Optional[KernelAction]:
        """Ask the LLM to generate an eBPF countermeasure.

        The LLM receives:
        - The threat signal data
        - Recent streaming RAG context (last 60s of kernel events)
        - Available eBPF templates as examples
        - Constraints (XDP/TC only, max map size, required stats)
        """
        # Build context for the LLM
        context = self._build_llm_context(signal)
        prompt = self._build_generation_prompt(signal, context)

        # Invoke LLM
        result = self._inference.chat(
            messages=[
                {"role": "system", "content": KERNEL_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=2048,
            backend="local",  # Prefer local for latency
        )

        if not result:
            logger.warning("LLM unavailable for kernel response")
            return None

        content = result["message"]["content"]

        # Extract C code from LLM response
        c_code = self._compiler.extract_code(content)
        if not c_code:
            logger.warning("LLM did not produce valid C code")
            return None

        # Compile and verify
        compilation = self._compiler.compile_and_verify(c_code)
        if not compilation.success:
            logger.warning("eBPF verification failed: %s", compilation.error)
            self._memory.store(
                "session", f"ebpf_fail_{int(time.time())}",
                f"eBPF verification failed for {signal.event_type}: {compilation.error}",
            )
            return None

        # Principle guard check
        safety = check_action(
            "KERNEL_ORCHESTRATOR",
            "deploy_ebpf",
            {"program_type": compilation.program_type, "signal": signal.event_type},
        )
        if not safety.safe:
            logger.warning("Principle guard blocked eBPF deployment: %s", safety.reason)
            return None

        # Novel programs require human approval
        if not template and safety.requires_confirmation:
            return self._queue_for_approval(compilation, signal)

        # Sandbox test
        sandbox_result = self._sandbox.test(
            compilation, duration_s=self.SANDBOX_DURATION_S
        )
        if not sandbox_result.passed:
            logger.warning("Sandbox test failed: %s", sandbox_result.reason)
            return None

        # Deploy to Reflex engine
        return self._deploy_to_reflex(compilation, signal)
```

### 4.3 `ebpf_compiler.py` — Safe Code Generation

```python
"""
eBPF Compiler — LLM output → verified BPF bytecode

Critical security component. The LLM generates C source code
that MUST be compiled and verified before loading.

Verification layers:
1. Static analysis: no banned functions, no unbounded loops
2. BPF verifier: kernel rejects unsafe programs
3. Behavioral sandbox: test against synthetic traffic
"""

# BANNED constructs that the LLM must never generate
BANNED_PATTERNS = [
    r'bpf_probe_write_user',     # Write to userspace memory
    r'bpf_override_return',       # Override syscall return (dangerous)
    r'system\s*\(',               # Shell command execution
    r'exec[lv]?[pe]?\s*\(',       # Process execution
    r'__attribute__\s*\(',        # GCC attributes (potential exploit)
    r'asm\s+volatile',            # Inline assembly
    r'#include\s*<(?!uapi|linux)', # Only kernel headers allowed
]

# ALLOWED BPF helpers (whitelist approach)
ALLOWED_HELPERS = {
    'bpf_map_lookup_elem', 'bpf_map_update_elem', 'bpf_map_delete_elem',
    'bpf_ktime_get_ns', 'bpf_get_prandom_u32',
    'bpf_xdp_adjust_head', 'bpf_xdp_adjust_tail',
    'bpf_get_current_pid_tgid', 'bpf_get_current_comm',
    'bpf_perf_event_output', 'bpf_ringbuf_output',
    'bpf_skb_store_bytes', 'bpf_l3_csum_replace', 'bpf_l4_csum_replace',
    'bpf_redirect', 'bpf_clone_redirect',
    'bpf_trace_printk',  # Debug only, rate-limited by kernel
}

# Maximum program complexity
MAX_INSTRUCTIONS = 4096            # BPF verifier default limit
MAX_MAP_ENTRIES = 65536
MAX_CODE_LENGTH = 8192             # Characters of C source
```

### 4.4 Integration with Existing Reflex Engine

The hot-swap mechanism extends `ReflexEngine` in `/home/ubuntu/hookprobe/core/aegis/reflex/engine.py`:

```python
# New method added to ReflexEngine class:

def hot_swap_program(
    self,
    program_id: str,
    bpf_object: Any,        # Compiled BPF object
    program_type: str,       # "xdp", "tc", "kprobe"
    attach_point: str,       # Interface or function name
    rollback_timeout_s: int = 300,
) -> bool:
    """Hot-swap an eBPF program generated by the Neuro-Kernel.

    This replaces the current program at the attach point atomically.
    The old program continues running until the new one is successfully
    attached (BPF_F_REPLACE flag on kernel 5.13+).

    Preserves map state if the new program uses compatible maps.
    """
    ...
```

### 4.5 New Orchestrator Routing Rules

Added to `ROUTING_RULES` in `/home/ubuntu/hookprobe/core/aegis/orchestrator.py`:

```python
# Neuro-Kernel routing
"napse.zero_day":           ["GUARDIAN", "KERNEL_ORCHESTRATOR"],
"kernel.ebpf_deployed":     ["MEDIC", "ORACLE"],
"kernel.ebpf_failed":       ["FORGE", "MEDIC"],
"kernel.rollback":          ["MEDIC"],
"kernel.anomaly":           ["GUARDIAN", "MEDIC"],
```

### 4.6 New Principle Guard Rules

Added to `IMMUTABLE_PRINCIPLES` in `/home/ubuntu/hookprobe/core/aegis/principle_guard.py`:

```python
"never_disable_kernel_safety": {
    "description": "Never deploy eBPF that bypasses kernel verifier or disables safety",
    "blocked_actions": [
        "bypass_verifier", "disable_bpf_jit_hardening", "load_unverified_bpf",
    ],
    "blocked_patterns": [
        r"bpf_probe_write_user",
        r"bpf_override_return",
        r"bypass.*verif",
    ],
},
"kernel_change_audit": {
    "description": "All kernel-level changes must be logged and reversible",
    "blocked_actions": [],
    "blocked_patterns": [],
},
```

### 4.7 New Tool Definitions

Added to `TOOL_REGISTRY` in `/home/ubuntu/hookprobe/core/aegis/tool_executor.py`:

```python
"deploy_ebpf": ToolDefinition(
    name="deploy_ebpf",
    description="Deploy a verified eBPF program to the kernel",
    parameters={...},
    agents=["GUARDIAN", "MEDIC"],
    requires_confirmation=True,  # Always requires human approval for novel programs
),
"rollback_ebpf": ToolDefinition(
    name="rollback_ebpf",
    description="Rollback a deployed eBPF program to previous version",
    parameters={...},
    agents=["GUARDIAN", "MEDIC"],
),
"list_kernel_programs": ToolDefinition(
    name="list_kernel_programs",
    description="List all active eBPF programs managed by Neuro-Kernel",
    parameters={...},
    agents=["GUARDIAN", "MEDIC", "ORACLE"],
),
```

---

## 5. Detailed Design: Layer 2 — Streaming eBPF-RAG

### 5.1 New Files

```
core/aegis/neurokernel/
    streaming_rag.py            # Main RAG pipeline
    event_chunker.py            # eBPF event → embeddable chunks
    vector_store.py             # ChromaDB/SQLite vector storage
    embedding_engine.py         # MiniLM or quantized embedding model
```

### 5.2 Data Flow: eBPF Event to Vector

```
 eBPF Sensors (kernel)
       │
       ▼
 perf_event_output / ring_buffer
       │
       ▼
 SensorManager.poll()  ──────────  1M+ events/sec raw
       │
       ▼
 EventChunker.chunk()  ──────────  Aggregate into 1s windows
       │                            per (src_ip, event_type)
       │                            ~1000 chunks/sec
       ▼
 EmbeddingEngine.embed()  ────────  MiniLM-L6-v2 (384-dim)
       │                            Batched, ~500 chunks/sec
       ▼
 VectorStore.upsert()  ──────────  Rolling 60s window
       │                            Max 60K vectors in store
       ▼
 LLM queries via similarity search
```

### 5.3 `event_chunker.py` — High-Volume Event Aggregation

```python
"""
Event Chunker — Converts raw eBPF events into embeddable text chunks.

The key insight: we do NOT embed individual syscalls. At 1M+ events/sec,
that is impossible. Instead, we aggregate into 1-second windows per
(source_ip, event_type) and produce a natural-language summary.

Example output chunk:
    "10.200.0.45 made 47 TCP connections to 5 unique destinations
    in 1s, 3 to port 443, 2 to port 80, with 12 failed DNS lookups
    for high-entropy domains (avg entropy 4.2 bits/char)"

This text chunk is then embedded into a 384-dim vector for similarity
search when the LLM needs situational context.
"""

@dataclass
class EventChunk:
    """A single embeddable chunk representing 1s of activity."""
    timestamp: float
    source_ip: str
    event_type: str           # "network", "syscall", "file", "dns"
    summary: str              # Natural language summary
    raw_count: int            # Number of raw events aggregated
    key_metrics: Dict[str, float]  # Numeric features for filtering
    embedding: Optional[List[float]] = None

    @property
    def chunk_id(self) -> str:
        return f"{self.source_ip}:{self.event_type}:{int(self.timestamp)}"
```

### 5.4 `vector_store.py` — Rolling Window Vector Storage

```python
"""
Vector Store — Rolling window vector database for streaming RAG.

Two implementations:
1. ChromaDB (Fortress/Nexus, 4GB+): Full vector DB with HNSW index
2. SQLite + numpy (Guardian, 1.5GB): Lightweight, brute-force search

The store maintains a rolling 60-second window. Older vectors are
evicted. This is NOT a persistent knowledge base — that is AEGIS
memory. This is ephemeral situational awareness.

Memory budget:
    60s window * 1000 chunks/s * 384 dims * 4 bytes = ~90MB
    With metadata overhead: ~128MB (fits in Fortress 4GB budget)
"""

class VectorStore:
    """Abstract base for vector storage."""

    def upsert(self, chunks: List[EventChunk]) -> int: ...
    def search(self, query: str, k: int = 10, time_window_s: float = 60.0) -> List[EventChunk]: ...
    def evict_older_than(self, cutoff_timestamp: float) -> int: ...
    def stats(self) -> Dict[str, Any]: ...


class ChromaVectorStore(VectorStore):
    """ChromaDB-backed store for Fortress/Nexus tiers."""
    ...

class SQLiteVectorStore(VectorStore):
    """SQLite + numpy brute-force store for Guardian tier.

    Uses a single table with BLOB-stored float32 vectors.
    Search is O(N) but N <= 60K so brute force is fast enough
    (~5ms for 60K vectors on RPi4).
    """
    ...
```

### 5.5 Integration with AEGIS Memory

The vector store is a **6th memory layer** (ephemeral, not persistent).
Integration point: `/home/ubuntu/hookprobe/core/aegis/memory.py`

```python
# New constant added:
LAYER_STREAMING = "streaming"  # Ephemeral vector store (not persisted to SQLite)

# MemoryManager gains a new method:
def recall_streaming_context(
    self,
    query: str,
    time_window_s: float = 60.0,
    k: int = 10,
) -> str:
    """Search the streaming RAG vector store for recent kernel events
    relevant to the query. Returns formatted context for LLM injection."""
    ...
```

### 5.6 `streaming_rag.py` — The Main Pipeline

```python
"""
Streaming eBPF-RAG Pipeline

Connects the eBPF sensor manager to the vector store via the chunker
and embedding engine. Runs as a background thread, continuously
ingesting kernel events and maintaining the rolling window.

The pipeline is pull-based from the LLM's perspective: when the LLM
needs context, it calls recall_streaming_context() which searches
the vector store. The ingestion runs independently.
"""

class StreamingRAGPipeline:
    """Background pipeline: sensors → chunks → vectors → searchable."""

    INGEST_INTERVAL_S = 1.0     # Process events every 1 second
    EVICTION_INTERVAL_S = 5.0   # Evict old vectors every 5 seconds
    WINDOW_SIZE_S = 60.0        # Keep 60 seconds of context
    MAX_CHUNKS_PER_TICK = 1000  # Backpressure limit

    def __init__(
        self,
        sensor_manager: SensorManager,
        chunker: EventChunker,
        embedder: EmbeddingEngine,
        store: VectorStore,
    ):
        ...

    def query(self, question: str, k: int = 10) -> str:
        """Semantic search across recent kernel events.

        Used by KernelOrchestrator._build_llm_context() to inject
        situational awareness into the LLM prompt.
        """
        chunks = self._store.search(question, k=k)
        return self._format_context(chunks)
```

---

## 6. Detailed Design: Layer 3 — Shadow Pentester

### 6.1 New Files

```
core/aegis/neurokernel/
    shadow_pentester.py         # Offensive LLM agent coordinator
    attack_library.py           # Parameterized attack templates
    defense_feedback.py         # Vulnerability → QSecBit update loop

products/nexus/lib/red_purple_teaming/
    kernel_twin.py              # eBPF-aware digital twin (extends digital_twin.py)
```

### 6.2 Architecture: Offensive vs Defensive Loop

```
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                        SHADOW PENTESTER LOOP                              │
  │                                                                           │
  │   ┌─────────────┐                              ┌─────────────┐           │
  │   │ OFFENSIVE   │──── finds vulnerability ────▶│ DEFENSIVE   │           │
  │   │ LLM AGENT   │                              │ FEEDBACK    │           │
  │   │             │◀─── deploys countermeasure ──│             │           │
  │   └──────┬──────┘                              └──────┬──────┘           │
  │          │                                            │                  │
  │          ▼                                            ▼                  │
  │   ┌─────────────┐                              ┌─────────────┐           │
  │   │ DIGITAL TWIN│                              │ QSECBIT     │           │
  │   │ (isolated)  │                              │ CLASSIFIER  │           │
  │   │ - Network   │                              │ UPDATE      │           │
  │   │ - eBPF logs │                              │             │           │
  │   │ - Services  │                              │ (new sig)   │           │
  │   └─────────────┘                              └─────────────┘           │
  │                                                                           │
  │   PRINCIPLE GUARD ENFORCEMENT:                                           │
  │   - Offensive agent runs ONLY in twin namespace                          │
  │   - Cannot access production network                                     │
  │   - Cannot disable any protection                                        │
  │   - All attack payloads logged to audit trail                            │
  │   - Rate-limited to prevent resource exhaustion                          │
  │                                                                           │
  └──────────────────────────────────────────────────────────────────────────┘
```

### 6.3 `shadow_pentester.py` — Offensive Agent

```python
"""
Shadow Pentester — Continuous Offensive Testing Agent

Runs as an AEGIS agent (registered as "SHADOW") that operates
exclusively within the Digital Twin environment. Uses LLM reasoning
to discover attack paths, then reports findings to the defensive side.

Extends the existing purple teaming orchestrator at:
    products/nexus/lib/red_purple_teaming/orchestrator.py

Key differences from existing orchestrator:
1. Autonomous — runs continuously, not on-demand
2. eBPF-aware — uses historical kernel telemetry as attack surface info
3. Closed-loop — findings auto-feed into QSecBit classifier updates
4. LLM-driven — uses the LLM for creative attack ideation, not just
   predefined 9-vector playbook
"""

class ShadowPentester:
    """Offensive LLM agent operating in the Digital Twin.

    Attack methodology:
    1. Reconnaissance: Query streaming RAG for network topology
    2. Vulnerability analysis: LLM identifies weak points
    3. Attack simulation: Execute in twin (no production impact)
    4. Impact assessment: Measure what defenses caught/missed
    5. Defensive feedback: Update QSecBit signatures
    """

    # Principle Guard: these are the ONLY actions allowed
    ALLOWED_ACTIONS = {
        "scan_twin_network",       # Nmap-like scan of twin
        "inject_twin_traffic",     # Send crafted packets in twin
        "replay_twin_ebpf",       # Replay captured eBPF events
        "query_twin_qsecbit",     # Check if twin's QSecBit detects
        "report_vulnerability",    # Report finding to defensive side
    }

    # BLOCKED actions (enforced by PrincipleGuard)
    BLOCKED_ACTIONS = {
        "scan_production",         # Never touch real network
        "inject_production",       # Never touch real network
        "disable_protection",      # Never disable defenses
        "exfiltrate_data",        # Never extract real data
    }
```

### 6.4 Digital Twin Isolation

The twin extends the existing `DigitalTwinSimulator` at
`/home/ubuntu/hookprobe/products/nexus/lib/red_purple_teaming/digital_twin.py`:

```python
# New file: products/nexus/lib/red_purple_teaming/kernel_twin.py

"""
Kernel-Aware Digital Twin — extends DigitalTwinSimulator with eBPF replay.

Adds:
1. Network namespace isolation (real Linux netns, not simulated)
2. eBPF event replay from historical streaming RAG data
3. Mini-NAPSE instance running inside the twin
4. QSecBit scoring of twin traffic for defense validation
"""

class KernelDigitalTwin(DigitalTwinSimulator):
    """Extends the virtual twin with real kernel isolation.

    Uses Linux network namespaces for actual packet-level isolation.
    The shadow pentester's traffic never leaves the namespace.

    Setup:
        ip netns add hookprobe-twin
        ip link add veth-twin-in type veth peer name veth-twin-out
        ip link set veth-twin-in netns hookprobe-twin
        # OVS bridge inside namespace mirrors production topology
    """
    ...
```

### 6.5 Defense Feedback Loop

```python
# New file: core/aegis/neurokernel/defense_feedback.py

"""
Defense Feedback — Vulnerability Report → QSecBit Signature

When the shadow pentester finds a vulnerability that QSecBit did not
detect, this module:
1. Extracts the attack signature (packet pattern, syscall sequence)
2. Generates a new QSecBit detection rule
3. Validates the rule against false positives in the twin
4. Deploys to production QSecBit via the existing signature updater

Integration point:
    core/qsecbit/signatures/updater.py — SignatureUpdater.add_signature()
    core/qsecbit/signatures/database.py — SignatureDatabase
"""
```

---

## 7. Detailed Design: Layer 4 — Hybrid Inference

### 7.1 New Files

```
core/aegis/neurokernel/
    hybrid_inference.py         # Edge/Nexus routing logic
    nexus_offload.py           # eBPF trace packaging and transport
    llm_monitor.py             # eBPF uprobes monitoring the LLM itself
    verdict.py                 # Verdict types (Allow/Drop/Investigate)
```

### 7.2 Fast Path vs Slow Path

```
                    INCOMING THREAT EVENT
                           │
                    ┌──────▼──────┐
                    │ QSecBit     │
                    │ Fast Path   │
                    │ (< 1ms)     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
              ┌─────│ Confidence  │─────┐
              │     │ > 0.90?     │     │
              │     └─────────────┘     │
              │                         │
         YES (99%)                 NO (1%)
              │                         │
              ▼                         ▼
    ┌─────────────┐            ┌─────────────┐
    │ LOCAL       │            │ PACKAGE      │
    │ VERDICT     │            │ eBPF TRACE   │
    │ (QSecBit/   │            │ (last 5s)    │
    │  0.5B model)│            └──────┬───────┘
    └─────────────┘                   │
                                      ▼
                              ┌─────────────┐
                              │ HTP         │
                              │ TRANSPORT   │
                              │ to Nexus    │
                              └──────┬──────┘
                                     │
                              ┌──────▼──────┐
                              │ NEXUS 8B    │
                              │ LLM REASON  │
                              │ (1-5s)      │
                              └──────┬──────┘
                                     │
                              ┌──────▼──────┐
                              │ VERDICT     │
                              │ Allow/Drop/ │
                              │ Investigate │
                              └─────────────┘
```

### 7.3 `nexus_offload.py` — Edge-to-Nexus Protocol

```python
"""
Nexus Offload — Package and transport eBPF traces to Nexus for deep analysis.

When the edge device (Sentinel/Guardian/Fortress) encounters an ambiguous
threat that QSecBit cannot classify with high confidence, this module:

1. Captures the last 5 seconds of relevant eBPF events
2. Packages them into a compact binary format
3. Sends via HTP transport (post-quantum encrypted)
4. Waits for Nexus verdict (with timeout and fallback)

New packet type in shared/mesh/unified_transport.py:
    KERNEL_EVENT = 0x60    # eBPF trace offload to Nexus
    KERNEL_VERDICT = 0x61  # Nexus verdict response

Memory budget for trace package: 64KB max (fits in single HTP frame)
"""
```

### 7.4 `llm_monitor.py` — LLM Self-Defense (eBPF Uprobes)

```python
"""
LLM Monitor — eBPF uprobes on the LLM inference process.

Monitors the Ollama/vLLM process for signs of compromise:
1. Syscall monitoring: unexpected file access, network connections
2. Memory monitoring: abnormal allocation patterns
3. Output monitoring: generated code contains banned patterns
4. Resource monitoring: CPU/memory exceeding budget

If compromise is detected, the kernel kills the LLM process
via bpf_send_signal(SIGKILL) before any malicious output can
be acted upon.

This is the "immune system watching the brain" — even if the
LLM is prompt-injected, the kernel-level monitor catches the
resulting anomalous behavior.
"""

LLM_MONITOR_PROGRAM = r'''
#include <uapi/linux/bpf.h>
#include <linux/sched.h>

// Monitor: if the LLM process (tracked by PID in llm_pids map)
// attempts to:
//   - connect() to an unexpected IP
//   - open() a file outside /tmp and model directories
//   - execve() any subprocess
// Then log the event and optionally kill the process.

BPF_HASH(llm_pids, u32, u8, 64);           // Tracked LLM PIDs
BPF_HASH(allowed_fds, u32, u8, 1024);      // Pre-approved file descriptors
BPF_PERF_OUTPUT(llm_events);               // Events to userspace

// Kprobe on __x64_sys_connect — catch outbound connections
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *tracked = llm_pids.lookup(&pid);
    if (!tracked) return 0;

    // LLM process is making an outbound connection
    // Log event for userspace analysis
    struct llm_event_t {
        u32 pid;
        u32 event_type;  // 1=connect, 2=open, 3=execve
        u64 timestamp;
    } evt = {};
    evt.pid = pid;
    evt.event_type = 1;
    evt.timestamp = bpf_ktime_get_ns();
    llm_events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Kprobe on __x64_sys_execve — kill if LLM tries to spawn subprocess
int kprobe__sys_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *tracked = llm_pids.lookup(&pid);
    if (!tracked) return 0;

    // LLM process trying to execute a subprocess — KILL
    bpf_send_signal(9);  // SIGKILL
    return 0;
}
'''
```

### 7.5 Tier-Appropriate Profiles

Updates to existing AEGIS profiles:

```python
# core/aegis/profiles/pico.py (Sentinel 256MB)
"neurokernel": {
    "enabled": False,        # No local LLM
    "receive_filters": True, # Can receive pre-built eBPF from Nexus
    "streaming_rag": False,
    "shadow_pentester": False,
    "llm_monitor": False,
}

# core/aegis/profiles/lite.py (Guardian 1.5GB)
"neurokernel": {
    "enabled": True,
    "mode": "offload",           # Offload complex to Nexus
    "fast_path_model": None,     # QSecBit only (no local model)
    "streaming_rag": False,      # Not enough RAM
    "shadow_pentester": False,
    "llm_monitor": False,
}

# core/aegis/profiles/full.py (Fortress 4GB)
"neurokernel": {
    "enabled": True,
    "mode": "hybrid",            # Local + Nexus offload
    "fast_path_model": "qwen2.5-coder:0.5b",
    "streaming_rag": True,
    "streaming_rag_window_s": 60,
    "streaming_rag_memory_mb": 128,
    "vector_store": "sqlite",    # Lightweight store
    "shadow_pentester": False,   # Nexus only
    "llm_monitor": True,
}

# core/aegis/profiles/deep.py (Nexus 16GB+)
"neurokernel": {
    "enabled": True,
    "mode": "full",              # Full local reasoning
    "fast_path_model": "llama-3.2:8b",
    "inference_engine": "vllm",  # vLLM for batched inference
    "streaming_rag": True,
    "streaming_rag_window_s": 300,  # 5 minutes
    "streaming_rag_memory_mb": 512,
    "vector_store": "chromadb",
    "shadow_pentester": True,
    "shadow_pentester_interval_s": 3600,  # Run every hour
    "llm_monitor": True,
}
```

---

## 8. Security Analysis

### 8.1 Threat Model

| Threat                             | Severity | Mitigation                                          |
|------------------------------------|----------|-----------------------------------------------------|
| LLM generates malicious eBPF      | CRITICAL | BPF verifier + static analysis + sandbox + approval |
| BPF verifier bypass (kernel bug)   | CRITICAL | Kernel patching, cap BPF, seccomp on LLM process   |
| Prompt injection → eBPF injection  | HIGH     | PrincipleGuard, input sanitization, output parsing  |
| LLM exfiltrates data via eBPF      | HIGH     | Whitelist BPF helpers, no bpf_probe_write_user      |
| Shadow pentester escapes twin      | HIGH     | Network namespace, no production network access     |
| Vector DB poisoning                | MEDIUM   | Rolling window eviction, source validation          |
| Resource exhaustion (eBPF programs)| MEDIUM   | MAX_ACTIVE_PROGRAMS=32, memory accounting           |
| eBPF map exhaustion                | MEDIUM   | Per-map size limits, total map memory cap            |
| Side-channel via eBPF timing       | LOW      | Stats aggregation, no per-packet timing exposed     |

### 8.2 Defense-in-Depth for LLM-Generated eBPF

```
    LLM Output (C source)
         │
    ┌────▼────┐
    │ LAYER 1 │ Static Analysis
    │         │ - No banned patterns (BANNED_PATTERNS list)
    │         │ - Only whitelisted BPF helpers
    │         │ - Max code length 8KB
    │         │ - No inline assembly
    └────┬────┘
         │ PASS
    ┌────▼────┐
    │ LAYER 2 │ BPF Verifier (Kernel)
    │         │ - Bounded loops (kernel 5.3+)
    │         │ - Memory safety (no out-of-bounds)
    │         │ - No dead code (verifier prunes)
    │         │ - Stack depth limit (512 bytes)
    └────┬────┘
         │ PASS
    ┌────▼────┐
    │ LAYER 3 │ Behavioral Sandbox
    │         │ - Load in isolated netns
    │         │ - Send synthetic traffic
    │         │ - Verify expected behavior (drops/passes)
    │         │ - Check for unexpected side effects
    │         │ - 30-second test window
    └────┬────┘
         │ PASS
    ┌────▼────┐
    │ LAYER 4 │ Principle Guard
    │         │ - Action checked: "deploy_ebpf"
    │         │ - Novel programs: requires_confirmation=True
    │         │ - Template programs: auto-approved
    │         │ - Rate limit: max 5 deploys/minute
    └────┬────┘
         │ PASS
    ┌────▼────┐
    │ LAYER 5 │ Production Deployment
    │         │ - BPF_F_REPLACE atomic swap
    │         │ - Rollback timer (300s)
    │         │ - Performance monitoring
    │         │ - Auto-rollback on anomaly
    └─────────┘
```

### 8.3 LLM Self-Defense Architecture

```
                    ┌─────────────────────────┐
                    │     Ollama / vLLM        │
                    │     LLM Process          │
                    │     (PID tracked)        │
                    └────────────┬─────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            │                    │                    │
    ┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐
    │  kprobe:      │   │  kprobe:      │   │  uprobe:      │
    │  tcp_connect  │   │  sys_execve   │   │  generate()   │
    │  (log+alert)  │   │  (SIGKILL)    │   │  (output scan)│
    └───────────────┘   └───────────────┘   └───────────────┘

    If LLM attempts:
    - Outbound connection → LOGGED, alerted to MEDIC
    - Subprocess execution → KILLED immediately
    - File access outside whitelist → LOGGED, alerted
    - Output contains banned patterns → BLOCKED before deployment
```

---

## 9. Data Flow Architecture (End-to-End)

### 9.1 Complete Flow: Zero-Day Detection to Kernel Response

```
TIMELINE: 0ms ─────────────────────────────────────────── 5000ms

   0ms   NAPSE detects anomalous packet pattern
         │
   1ms   NAPSEBridge.poll() reads eve.json line
         │
   2ms   StandardSignal created (source="napse", severity="HIGH")
         │
   3ms   Orchestrator.process_signal() routes to GUARDIAN + KERNEL_ORCHESTRATOR
         │
  10ms   KernelOrchestrator.handle_signal() receives signal
         │
  15ms   Template registry check: no match (novel pattern)
         │
  20ms   StreamingRAGPipeline.query("anomalous packets from 10.200.0.45")
         │ Returns: "10.200.0.45 made 247 connections in 3s to 43 unique
         │          ports, SYN-only (no ACK), TTL=64, window=1024"
         │
  50ms   LLM invoked with context + signal + template examples
         │
 500ms   LLM generates XDP program:
         │   "Drop packets from src_ip matching observed pattern:
         │    SYN-only + TTL=64 + window=1024 + rate > 100/s"
         │
 510ms   EBPFCompiler.compile_and_verify():
         │   - Static analysis: PASS (no banned patterns)
         │   - BPF verifier: PASS (bounded, safe)
         │
 520ms   PrincipleGuard check: requires_confirmation=True (novel program)
         │
 530ms   OPTION A: Template match close enough → auto-approve
         │ OPTION B: Queue for human approval
         │
 560ms   EBPFSandbox.test(): 30s test with synthetic traffic
         │   - Synthetic packets matching pattern: DROPPED (correct)
         │   - Synthetic normal traffic: PASSED (correct)
         │   - No side effects detected
         │
 600ms   ReflexEngine.hot_swap_program(): atomic replacement
         │
 601ms   FIRST MALICIOUS PACKET DROPPED AT NIC LEVEL (XDP)
         │
5000ms   Rollback timer set: if QSecBit score does not improve
         │ within 300s, auto-rollback to previous program
         │
         Audit: MemoryManager.log_decision() records everything
         Mesh: Gossip threat intel to other nodes
         Cortex: Visualization updated with new kernel filter
```

### 9.2 Mesh Propagation of Kernel Filters

When a Fortress generates a verified eBPF filter, it can propagate to other nodes:

```python
# New packet type in shared/mesh/unified_transport.py

class PacketType(IntEnum):
    ...
    KERNEL_FILTER = 0x60       # Propagate verified eBPF filter
    KERNEL_VERDICT = 0x61      # Nexus verdict response
    KERNEL_TELEMETRY = 0x62    # eBPF trace offload
```

The filter is serialized as:
```
[4 bytes] filter_id (SHA256 prefix)
[2 bytes] program_type (XDP=1, TC=2, kprobe=3)
[2 bytes] program_length
[N bytes] compiled BPF bytecode (NOT C source — pre-verified)
[32 bytes] signature (node's Neuro weight signature)
```

Receiving nodes:
- **Sentinel**: Load pre-compiled filter directly (no LLM needed)
- **Guardian**: Verify signature, load if trusted node
- **Fortress**: Verify signature, optionally re-verify via local BPF verifier
- **Nexus**: Add to filter database for meta-analysis

---

## 10. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

**Goal**: Sensor infrastructure + template-based kernel response

| Task | Files | Complexity | Dependencies |
|------|-------|------------|--------------|
| Create `core/aegis/neurokernel/` module structure | `__init__.py`, `types.py` | Low | None |
| Implement `SensorManager` for eBPF event collection | `sensor_manager.py` | Medium | BCC installed |
| Implement `TemplateRegistry` with 10 pre-built filters | `ebpf_template_registry.py` | Medium | Reflex eBPF patterns |
| Implement `EBPFCompiler` static analysis + verifier wrapper | `ebpf_compiler.py`, `ebpf_verifier_wrapper.py` | High | BCC, kernel 5.15+ |
| Add new Principle Guard rules for kernel actions | Edit `principle_guard.py` | Low | None |
| Add new tool definitions for kernel operations | Edit `tool_executor.py` | Low | None |
| Add new routing rules to orchestrator | Edit `orchestrator.py` | Low | None |
| Create `EBPFSandbox` for isolated testing | `ebpf_sandbox.py` | High | Network namespaces |
| Wire `KernelOrchestrator` template path only | `kernel_orchestrator.py` | Medium | All above |
| Integration tests for template deployment | `tests/test_neurokernel.py` | Medium | All above |

**Deliverable**: Template-based eBPF deployment via AEGIS orchestrator.
Known patterns auto-deploy verified eBPF at NIC level.

### Phase 2: Streaming RAG (Weeks 5-8)

**Goal**: Real-time situational awareness via vector-embedded kernel events

| Task | Files | Complexity | Dependencies |
|------|-------|------------|--------------|
| Implement `EventChunker` with aggregation | `event_chunker.py` | Medium | SensorManager |
| Implement `EmbeddingEngine` (MiniLM) | `embedding_engine.py` | Medium | sentence-transformers |
| Implement `SQLiteVectorStore` | `vector_store.py` | Medium | numpy |
| Implement `ChromaVectorStore` | `vector_store.py` | Medium | chromadb |
| Build `StreamingRAGPipeline` | `streaming_rag.py` | High | All above |
| Integrate with AEGIS Memory (Layer 6) | Edit `memory.py` | Low | Pipeline |
| Add tier-appropriate vector store selection | Edit profiles | Low | Both stores |
| Performance benchmarks on RPi4 | `tests/benchmark_rag.py` | Medium | Full pipeline |

**Deliverable**: LLM queries return up-to-the-second kernel context.
"What happened in the last 60 seconds?" produces actionable summaries.

### Phase 3: LLM Code Generation (Weeks 9-14)

**Goal**: LLM generates novel eBPF programs for zero-day response

| Task | Files | Complexity | Dependencies |
|------|-------|------------|--------------|
| Design LLM system prompt for eBPF generation | `kernel_orchestrator.py` | High | Phase 1 templates as examples |
| Implement LLM output parsing (extract C code) | `ebpf_compiler.py` | Medium | Regex + AST |
| Extend `KernelOrchestrator` with LLM path | `kernel_orchestrator.py` | High | Phases 1+2 |
| Implement hot-swap in ReflexEngine | Edit `reflex/engine.py` | High | BPF_F_REPLACE support |
| Auto-rollback mechanism | `kernel_orchestrator.py` | Medium | Hot-swap |
| Human approval workflow via tool_executor | Edit `tool_executor.py` | Medium | Existing confirmation flow |
| End-to-end test: NAPSE event → LLM → eBPF → drop | `tests/test_kernel_e2e.py` | High | Full pipeline |

**Deliverable**: Zero-day detection triggers LLM-generated kernel filter.
Novel eBPF programs deployed within seconds of detection.

### Phase 4: Shadow Pentester (Weeks 15-20)

**Goal**: Continuous offensive testing in isolated digital twin

| Task | Files | Complexity | Dependencies |
|------|-------|------------|--------------|
| Implement `KernelDigitalTwin` with netns | `kernel_twin.py` | High | Existing digital_twin.py |
| Implement `ShadowPentester` offensive agent | `shadow_pentester.py` | High | Phase 3 LLM |
| Implement `AttackLibrary` parameterized attacks | `attack_library.py` | Medium | Existing 9 vectors |
| Implement `DefenseFeedback` → QSecBit loop | `defense_feedback.py` | High | QSecBit signatures |
| Integrate with existing PurpleTeamOrchestrator | Edit `orchestrator.py` (nexus) | Medium | Existing purple team |
| Principle Guard for offensive agent | Edit `principle_guard.py` | Medium | SHADOW agent rules |
| Continuous mode (hourly campaigns) | `shadow_pentester.py` | Medium | All above |

**Deliverable**: Autonomous red team finds vulnerabilities, blue team
auto-patches QSecBit classifiers. Continuous improvement loop.

### Phase 5: Hybrid Inference + LLM Monitor (Weeks 21-26)

**Goal**: Edge-Nexus offload + LLM self-defense

| Task | Files | Complexity | Dependencies |
|------|-------|------------|--------------|
| Implement `NexusOffload` protocol | `nexus_offload.py` | High | HTP transport |
| Add KERNEL_EVENT packet to mesh transport | Edit `unified_transport.py` | Medium | PacketType enum |
| Implement edge fast-path with 0.5B model | `hybrid_inference.py` | Medium | Ollama + qwen2.5-coder |
| Implement `LLMMonitor` eBPF uprobes | `llm_monitor.py` | High | BCC, uprobe support |
| Implement mesh propagation of kernel filters | Edit `mesh_bridge.py` | High | Gossip protocol |
| Sentinel receive-only filter loading | Edit `profiles/pico.py` | Low | Filter format |
| Verdict protocol (Allow/Drop/Investigate) | `verdict.py` | Low | Types |
| Cross-tier integration testing | `tests/test_hybrid.py` | High | Multiple tiers |

**Deliverable**: Full hybrid inference with edge fast-path, Nexus deep
analysis, and kernel-level LLM self-defense.

---

## 11. Risk Analysis and Mitigations

### 11.1 Critical Risks

**RISK 1: BPF Verifier Bypass**
- Probability: Low (kernel team actively patches)
- Impact: CRITICAL (arbitrary kernel code execution)
- Mitigation:
  - Keep kernel patched (automated via deploy/edge/update.sh)
  - Disable unprivileged BPF (`sysctl kernel.unprivileged_bpf_disabled=2`)
  - Cap BPF complexity below verifier limits (MAX_INSTRUCTIONS=4096)
  - Secondary static analysis before verifier
  - Monitor CVEs for BPF verifier bugs

**RISK 2: LLM Prompt Injection Leading to Malicious eBPF**
- Probability: Medium (adversary controls some input data)
- Impact: HIGH (crafted eBPF could drop legitimate traffic)
- Mitigation:
  - NAPSE event data is pre-parsed by NAPSEBridge (not raw strings)
  - PrincipleGuard sanitizes all LLM inputs
  - LLM output goes through 5-layer verification pipeline
  - Novel programs require human approval
  - Auto-rollback if QSecBit score degrades

**RISK 3: Shadow Pentester Escaping the Twin**
- Probability: Low (Linux netns is well-tested)
- Impact: HIGH (offensive tools on production network)
- Mitigation:
  - Separate network namespace (kernel-enforced isolation)
  - No IP routes to production from twin namespace
  - Twin has no credentials for production services
  - Offensive agent's tool whitelist enforced by PrincipleGuard
  - All twin traffic logged

**RISK 4: Resource Exhaustion on Constrained Devices**
- Probability: Medium (especially on Sentinel/Guardian)
- Impact: MEDIUM (degraded security performance)
- Mitigation:
  - Tier-appropriate profiles disable heavy features
  - MAX_ACTIVE_PROGRAMS limit prevents eBPF map exhaustion
  - Streaming RAG has memory cap (128MB on Fortress)
  - Guardian offloads to Nexus rather than local reasoning
  - Sentinel is receive-only (no LLM, no RAG)

**RISK 5: LLM Latency Causing Detection Gaps**
- Probability: Medium (LLM inference is 100ms-5s)
- Impact: MEDIUM (attack proceeds during reasoning)
- Mitigation:
  - QSecBit fast path handles 99% of known threats (< 1ms)
  - Template-based eBPF deployment is instant (no LLM needed)
  - LLM path is for novel threats only
  - During LLM reasoning, existing Reflex levels apply
  - Worst case: 5s gap for truly novel zero-day

### 11.2 Operational Risks

| Risk | Probability | Mitigation |
|------|-------------|------------|
| BCC not available (ARM containers) | High | Fallback to iptables/tc (existing pattern in Reflex) |
| Ollama model download fails | Medium | Template-only mode, cloud fallback via OpenRouter |
| ChromaDB memory leak | Low | SQLite fallback store, periodic restart |
| eBPF map memory limit reached | Medium | Eviction of oldest entries, configurable limits |
| Multiple nodes deploy conflicting filters | Low | Filter dedup by content hash, priority system |

---

## 12. Technology Selection Rationale

### 12.1 Embedding Model: MiniLM-L6-v2

| Option | Dimensions | Speed (RPi4) | RAM | Decision |
|--------|-----------|---------------|-----|----------|
| MiniLM-L6-v2 | 384 | 50 chunks/s | 80MB | SELECTED |
| all-MiniLM-L12-v2 | 384 | 25 chunks/s | 120MB | Too slow for RPi |
| BGE-small-en | 384 | 40 chunks/s | 90MB | Alternative |
| nomic-embed-text | 768 | 15 chunks/s | 200MB | Too heavy |

Rationale: MiniLM-L6-v2 is the sweet spot for constrained hardware.
384 dimensions with 50 chunks/s on RPi4 is sufficient for our 1-second
aggregation windows.

### 12.2 Vector Database

| Option | RAM (60K vectors) | Query Time | Persistence | Decision |
|--------|-------------------|------------|-------------|----------|
| ChromaDB | ~200MB | 2ms | SQLite backend | Nexus only |
| SQLite + numpy | ~90MB | 5ms (brute) | SQLite | Guardian/Fortress |
| Milvus | 500MB+ | 1ms | Standalone | Too heavy |
| FAISS | ~100MB | 1ms | In-memory only | No persistence |

Rationale: Two-tier approach. SQLite+numpy brute-force for edge (60K vectors
searched in 5ms is fast enough). ChromaDB with HNSW for Nexus where we keep
300s windows.

### 12.3 LLM for eBPF Generation

| Option | Size | Speed | Code Quality | Decision |
|--------|------|-------|-------------|----------|
| Qwen2.5-Coder:0.5b | 500MB | 50 tok/s RPi | Good for templates | Fast path (Fortress) |
| Qwen2.5-Coder:3b | 2GB | 15 tok/s RPi | Good eBPF generation | Fortress hybrid |
| Llama-3.2:8b | 5GB | N/A on RPi | Excellent reasoning | Nexus only |
| CodeLlama:13b | 8GB | N/A on RPi | Best code generation | Nexus only |

Rationale: Qwen2.5-Coder family for code generation. 0.5b for fast-path
classification on Fortress, 3b for local eBPF generation when needed,
8b+ on Nexus for complex reasoning. The LLM NEVER runs on Sentinel or
Guardian.

### 12.4 Orchestration Framework

| Option | Decision | Rationale |
|--------|----------|-----------|
| LangGraph | NOT SELECTED | Adds heavy dependency, AEGIS orchestrator already handles routing |
| CrewAI | NOT SELECTED | Same — AEGIS agent registry + orchestrator is sufficient |
| Native AEGIS | SELECTED | Extend existing orchestrator with kernel routing rules |

The existing AEGIS orchestrator (`core/aegis/orchestrator.py`) with its
rule-based routing, agent registry, and tool executor pipeline is already
a capable orchestration framework. Adding LangGraph or CrewAI would
introduce unnecessary dependencies and complexity. The Shadow Pentester
is simply a new AEGIS agent ("SHADOW") with restricted tool permissions.

---

## 13. File Summary: All New and Modified Files

### New Files (23 files)

```
core/aegis/neurokernel/
    __init__.py                         # Module init + exports
    ARCHITECTURE.md                     # This document
    types.py                            # KernelAction, CompilationResult, etc.
    kernel_orchestrator.py              # Central closed-loop coordinator
    ebpf_compiler.py                    # LLM output → verified eBPF
    ebpf_template_registry.py           # Pre-built filter templates
    ebpf_sandbox.py                     # Isolated test environment (netns)
    ebpf_verifier_wrapper.py            # Python wrapper for BPF verifier
    sensor_manager.py                   # eBPF sensor lifecycle management
    streaming_rag.py                    # Main RAG pipeline
    event_chunker.py                    # High-volume event aggregation
    vector_store.py                     # ChromaDB/SQLite vector storage
    embedding_engine.py                 # MiniLM embedding model
    shadow_pentester.py                 # Offensive LLM agent
    attack_library.py                   # Parameterized attack templates
    defense_feedback.py                 # Vulnerability → QSecBit loop
    hybrid_inference.py                 # Edge/Nexus routing logic
    nexus_offload.py                    # eBPF trace transport to Nexus
    llm_monitor.py                      # eBPF uprobes on LLM process
    verdict.py                          # Verdict types (Allow/Drop/Investigate)

products/nexus/lib/red_purple_teaming/
    kernel_twin.py                      # eBPF-aware digital twin

tests/
    test_neurokernel.py                 # Unit + integration tests
    test_neurokernel_e2e.py             # End-to-end flow tests
```

### Modified Files (11 files)

```
core/aegis/orchestrator.py              # New routing rules for kernel events
core/aegis/principle_guard.py           # New kernel safety principles
core/aegis/tool_executor.py             # New kernel tools (deploy/rollback/list)
core/aegis/memory.py                    # Streaming layer integration
core/aegis/inference.py                 # vLLM backend option
core/aegis/reflex/engine.py             # hot_swap_program() method
core/aegis/profiles/pico.py             # neurokernel config
core/aegis/profiles/lite.py             # neurokernel config
core/aegis/profiles/full.py             # neurokernel config
core/aegis/profiles/deep.py             # neurokernel config
shared/mesh/unified_transport.py        # KERNEL_EVENT/VERDICT packet types
```

---

## 14. Dependency Matrix

```
Phase 1 (Foundation)
    └── Phase 2 (Streaming RAG) ── requires SensorManager from Phase 1
    └── Phase 3 (LLM Code Gen) ── requires TemplateRegistry + Sandbox from Phase 1
        └── Phase 4 (Shadow Pentester) ── requires LLM code gen from Phase 3
        └── Phase 5 (Hybrid + Monitor) ── requires LLM code gen from Phase 3

Phase 2 and Phase 3 can proceed in parallel after Phase 1.
Phases 4 and 5 can proceed in parallel after Phase 3.
```

Minimum viable: Phase 1 alone delivers value (template-based kernel defense).
Each subsequent phase is additive.

---

## 15. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Template eBPF deployment latency | < 10ms | From signal to XDP_DROP |
| LLM eBPF generation latency | < 5s | From signal to sandbox entry |
| Streaming RAG query latency | < 50ms | Vector search on 60K vectors |
| Zero-day → kernel filter time | < 30s | End-to-end (with sandbox) |
| False positive rate (eBPF blocks) | < 1% | Legitimate traffic incorrectly dropped |
| Shadow pentester finding rate | > 2/week | Unique vulnerabilities discovered |
| Memory overhead (Fortress) | < 256MB | Total Neuro-Kernel memory |
| CPU overhead (idle, Fortress) | < 3% | Sensor + RAG background load |
| BPF verifier pass rate | 100% | LLM-generated programs that pass verifier |
| Auto-rollback rate | < 5% | Deployed filters that required rollback |
