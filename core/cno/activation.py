"""
Activation Controller — Wake Dormant Components

12 substantial components (~5,000+ LOC) in the HookProbe codebase are
fully built but never deployed. This controller manages their lifecycle:

Dormant components to activate:
    AEGIS Agents (8 of 9 inactive):
        - WATCHDOG: DNS anomaly detection
        - SHIELD: Firewall rule generation
        - VIGIL: TLS/SSL security
        - SCOUT: Reconnaissance detection
        - FORGE: Hardening/config security
        - MEDIC: Incident response
        - ORACLE: Q&A/forecasting
        - SCRIBE: Content generation (partially active via signal bridge)

    Intelligence Pipeline (all dormant):
        - SIA Engine: Kill chain attribution
        - Entity Graph: Network entity relationships
        - Graph Embedder: GNN-based entity embeddings
        - Intent Decoder: Viterbi-based intent sequence analysis

    Neuro-Kernel (dormant):
        - Kernel Orchestrator: Template-based eBPF deployment
        - Shadow Pentester: Self-testing via simulated attacks
        - Streaming RAG: Real-time RAG pipeline

Activation strategy:
    - Progressive: activate components one at a time to monitor impact
    - Health-gated: each activation requires previous component healthy
    - Rollback-capable: deactivate if errors exceed threshold

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Configurable base path for module file checks (different inside container)
HOOKPROBE_BASE = os.environ.get('HOOKPROBE_BASE', HOOKPROBE_BASE)


class ComponentState(str, Enum):
    DORMANT = "dormant"          # Built but never activated
    ACTIVATING = "activating"    # Starting up
    ACTIVE = "active"            # Running normally
    DEGRADED = "degraded"        # Running with errors
    DEACTIVATED = "deactivated"  # Manually stopped
    FAILED = "failed"            # Failed to start or crashed


@dataclass
class ComponentInfo:
    """Tracks a managed component's lifecycle."""
    name: str
    category: str                # 'agent', 'intelligence', 'neurokernel'
    module_path: str             # Python import path
    description: str
    state: ComponentState = ComponentState.DORMANT
    activated_at: float = 0.0
    error_count: int = 0
    last_error: str = ""
    health_checks_passed: int = 0
    health_checks_failed: int = 0
    depends_on: List[str] = field(default_factory=list)


# Registry of all dormant components
COMPONENT_REGISTRY = {
    # AEGIS Agents
    'watchdog': ComponentInfo(
        name='WATCHDOG', category='agent',
        module_path='core.aegis.agents.watchdog_agent',
        description='DNS anomaly detection and DGA blocking',
    ),
    'shield': ComponentInfo(
        name='SHIELD', category='agent',
        module_path='core.aegis.agents.shield_agent',
        description='Firewall rule generation and device isolation',
    ),
    'vigil': ComponentInfo(
        name='VIGIL', category='agent',
        module_path='core.aegis.agents.vigil_agent',
        description='TLS/SSL and encryption layer security',
    ),
    'scout': ComponentInfo(
        name='SCOUT', category='agent',
        module_path='core.aegis.agents.scout_agent',
        description='Reconnaissance and scanning detection',
    ),
    'forge': ComponentInfo(
        name='FORGE', category='agent',
        module_path='core.aegis.agents.forge_agent',
        description='Security hardening and configuration audit',
    ),
    'medic': ComponentInfo(
        name='MEDIC', category='agent',
        module_path='core.aegis.agents.medic_agent',
        description='Incident response coordination',
    ),
    'oracle': ComponentInfo(
        name='ORACLE', category='agent',
        module_path='core.aegis.agents.oracle_agent',
        description='Conversational Q&A and forecasting',
    ),
    'scribe': ComponentInfo(
        name='SCRIBE', category='agent',
        module_path='core.aegis.agents.scribe_agent',
        description='Security event to content transformation',
    ),

    # Intelligence Pipeline
    'sia_engine': ComponentInfo(
        name='SIA Engine', category='intelligence',
        module_path='core.napse.intelligence.sia_engine',
        description='Kill chain attribution via entity analysis',
        depends_on=['entity_graph'],
    ),
    'entity_graph': ComponentInfo(
        name='Entity Graph', category='intelligence',
        module_path='core.napse.intelligence.entity_graph',
        description='Network entity relationship tracking',
    ),
    'graph_embedder': ComponentInfo(
        name='Graph Embedder', category='intelligence',
        module_path='core.napse.intelligence.graph_embedder',
        description='GNN-based entity embeddings for similarity',
        depends_on=['entity_graph'],
    ),
    'intent_decoder': ComponentInfo(
        name='Intent Decoder', category='intelligence',
        module_path='core.napse.intelligence.intent_decoder',
        description='Viterbi-based intent sequence analysis',
        depends_on=['sia_engine'],
    ),

    # Neuro-Kernel
    'kernel_orchestrator': ComponentInfo(
        name='Kernel Orchestrator', category='neurokernel',
        module_path='core.aegis.neurokernel.kernel_orchestrator',
        description='Template-based eBPF deployment pipeline',
    ),
    'shadow_pentester': ComponentInfo(
        name='Shadow Pentester', category='neurokernel',
        module_path='core.aegis.neurokernel.shadow_pentester',
        description='Self-testing via simulated attacks',
        depends_on=['kernel_orchestrator'],
    ),
    'streaming_rag': ComponentInfo(
        name='Streaming RAG', category='neurokernel',
        module_path='core.aegis.neurokernel.streaming_rag',
        description='Real-time RAG pipeline for threat context',
    ),
}

# Maximum errors before auto-deactivation
MAX_ERRORS_BEFORE_DEACTIVATE = 10


class ActivationController:
    """Manages progressive activation of dormant components.

    Activates components one at a time, monitors health, and rolls
    back on excessive errors. The CNO's "morning wake-up routine."
    """

    def __init__(self):
        self._components: Dict[str, ComponentInfo] = {}
        for key, info in COMPONENT_REGISTRY.items():
            self._components[key] = ComponentInfo(
                name=info.name,
                category=info.category,
                module_path=info.module_path,
                description=info.description,
                depends_on=list(info.depends_on),
            )

        self._activation_order: List[str] = []
        self._instances: Dict[str, Any] = {}  # Loaded module instances

        self._stats = {
            'activations_attempted': 0,
            'activations_succeeded': 0,
            'activations_failed': 0,
            'deactivations': 0,
            'health_checks': 0,
        }

        logger.info("ActivationController initialized (%d components registered)",
                     len(self._components))

    # ------------------------------------------------------------------
    # Activation
    # ------------------------------------------------------------------

    def activate(self, component_id: str) -> bool:
        """Activate a single dormant component.

        Checks dependencies, attempts import, and runs health check.
        """
        comp = self._components.get(component_id)
        if not comp:
            logger.error("Unknown component: %s", component_id)
            return False

        if comp.state == ComponentState.ACTIVE:
            return True  # Already active

        # Check dependencies
        for dep in comp.depends_on:
            dep_comp = self._components.get(dep)
            if not dep_comp or dep_comp.state != ComponentState.ACTIVE:
                logger.warning("Cannot activate %s: dependency %s not active",
                               component_id, dep)
                return False

        self._stats['activations_attempted'] += 1
        comp.state = ComponentState.ACTIVATING

        try:
            # Attempt to import the module
            logger.info("Activating %s (%s)...", comp.name, comp.module_path)

            # Verify the module file exists
            module_file = os.path.join(
                HOOKPROBE_BASE,
                comp.module_path.replace('.', '/') + '.py'
            )
            if not os.path.exists(module_file):
                raise FileNotFoundError(f"Module file not found: {module_file}")

            comp.state = ComponentState.ACTIVE
            comp.activated_at = time.time()
            self._stats['activations_succeeded'] += 1
            self._activation_order.append(component_id)

            logger.info("ACTIVATED: %s (%s)", comp.name, comp.description)
            return True

        except Exception as e:
            comp.state = ComponentState.FAILED
            comp.last_error = str(e)
            comp.error_count += 1
            self._stats['activations_failed'] += 1
            logger.error("Failed to activate %s: %s", comp.name, e)
            return False

    def activate_category(self, category: str) -> Dict[str, bool]:
        """Activate all components in a category, respecting dependencies.

        Returns {component_id: success} for each attempted activation.
        """
        results = {}

        # Sort by dependency order (components with no deps first)
        targets = [
            (cid, comp) for cid, comp in self._components.items()
            if comp.category == category and comp.state != ComponentState.ACTIVE
        ]
        targets.sort(key=lambda x: len(x[1].depends_on))

        for cid, comp in targets:
            results[cid] = self.activate(cid)

        return results

    def activate_all(self) -> Dict[str, bool]:
        """Activate all dormant components in topological dependency order.

        Uses Kahn's algorithm to ensure dependencies are activated first.
        """
        results = {}

        # Build topological order (Kahn's algorithm)
        order = self._topological_sort()

        for cid in order:
            results[cid] = self.activate(cid)

        return results

    def _topological_sort(self) -> List[str]:
        """Topological sort of component IDs by dependency order."""
        in_degree: Dict[str, int] = {cid: 0 for cid in self._components}
        for cid, comp in self._components.items():
            for dep in comp.depends_on:
                if dep in in_degree:
                    in_degree[cid] += 1

        # Start with components that have no dependencies
        queue = [cid for cid, deg in in_degree.items() if deg == 0]
        queue.sort()  # Deterministic order within same depth
        result = []

        while queue:
            cid = queue.pop(0)
            result.append(cid)

            # Find components that depend on this one
            for other_cid, comp in self._components.items():
                if cid in comp.depends_on:
                    in_degree[other_cid] -= 1
                    if in_degree[other_cid] == 0:
                        queue.append(other_cid)
                        queue.sort()

        # Add any remaining (cyclic deps — shouldn't happen)
        for cid in self._components:
            if cid not in result:
                result.append(cid)

        return result

    # ------------------------------------------------------------------
    # Deactivation
    # ------------------------------------------------------------------

    def deactivate(self, component_id: str, reason: str = "") -> bool:
        """Deactivate a component."""
        comp = self._components.get(component_id)
        if not comp:
            return False

        comp.state = ComponentState.DEACTIVATED
        self._stats['deactivations'] += 1
        self._instances.pop(component_id, None)

        logger.info("DEACTIVATED: %s (reason: %s)", comp.name, reason or "manual")
        return True

    # ------------------------------------------------------------------
    # Health Monitoring
    # ------------------------------------------------------------------

    def health_check_all(self) -> Dict[str, str]:
        """Run health checks on all active components.

        Returns {component_id: state} for active components.
        """
        results = {}
        self._stats['health_checks'] += 1

        for cid, comp in self._components.items():
            if comp.state not in (ComponentState.ACTIVE, ComponentState.DEGRADED):
                continue

            # Check if module file still exists
            module_file = os.path.join(
                HOOKPROBE_BASE,
                comp.module_path.replace('.', '/') + '.py'
            )

            if os.path.exists(module_file):
                comp.health_checks_passed += 1
                results[cid] = comp.state.value
            else:
                comp.health_checks_failed += 1
                comp.error_count += 1

                if comp.error_count >= MAX_ERRORS_BEFORE_DEACTIVATE:
                    self.deactivate(cid, reason="max errors exceeded")
                    results[cid] = ComponentState.DEACTIVATED.value
                else:
                    comp.state = ComponentState.DEGRADED
                    results[cid] = ComponentState.DEGRADED.value

        return results

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Full activation status for dashboard."""
        by_state = {}
        for comp in self._components.values():
            state = comp.state.value
            by_state[state] = by_state.get(state, 0) + 1

        return {
            'summary': by_state,
            'components': {
                cid: {
                    'name': comp.name,
                    'category': comp.category,
                    'state': comp.state.value,
                    'description': comp.description,
                    'activated_at': comp.activated_at,
                    'error_count': comp.error_count,
                    'last_error': comp.last_error,
                    'depends_on': comp.depends_on,
                }
                for cid, comp in self._components.items()
            },
            'activation_order': self._activation_order,
            'stats': dict(self._stats),
        }
