"""
Fortress AI vs AI Integration

Integrates the core AI vs AI module with Fortress threat detection.
Provides simplified interface for LSTM predictions, IoC generation,
and defense orchestration.

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

# Import core AI vs AI module
try:
    from core.ai_vs_ai import (
        ThreatPredictor,
        IoCGenerator,
        DefenseOrchestrator,
        ComputeEvaluator,
        IoC,
        ThreatPrediction,
        DefenseStrategy,
        DefenseAction,
        ComputeTier,
        ComputeTask,
    )
    AI_VS_AI_AVAILABLE = True
except ImportError:
    AI_VS_AI_AVAILABLE = False
    print("Warning: core.ai_vs_ai module not available")


# Configuration paths
CONFIG_DIR = Path("/etc/hookprobe")
DATA_DIR = Path("/opt/hookprobe/fortress/data")
IOC_DIR = DATA_DIR / "ioc"
MODEL_DIR = DATA_DIR / "ml-models"


class FortressAIIntegration:
    """
    Fortress AI integration for threat detection and response.

    Provides:
    - LSTM-based attack prediction (statistical fallback if no PyTorch)
    - IoC generation with MITRE ATT&CK mapping
    - Defense strategy recommendations
    - Nexus offloading for complex tasks
    """

    def __init__(
        self,
        enable_nexus_offload: bool = True,
        enable_ai_consultation: bool = False,  # Disabled by default on Fortress
        n8n_url: Optional[str] = None
    ):
        if not AI_VS_AI_AVAILABLE:
            raise ImportError("core.ai_vs_ai module required")

        # Detect system capabilities
        self.compute_tier = self._detect_tier()

        # Initialize components
        self.predictor = ThreatPredictor(compute_tier=self.compute_tier)
        self.ioc_generator = IoCGenerator(output_dir=IOC_DIR)
        self.orchestrator = DefenseOrchestrator(
            compute_tier=self.compute_tier,
            n8n_url=n8n_url,
        )
        self.evaluator = ComputeEvaluator(local_tier=self.compute_tier)

        # Configuration
        self.enable_nexus_offload = enable_nexus_offload
        self.enable_ai_consultation = enable_ai_consultation

        # Response handlers
        self._response_handlers: List[Callable[[DefenseStrategy], None]] = []

        # Statistics
        self._events_processed = 0
        self._iocs_generated = 0
        self._strategies_created = 0
        self._nexus_offloads = 0

        # Load saved state
        self._load_state()

    def _detect_tier(self) -> ComputeTier:
        """Detect compute tier based on system resources"""
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        mem_kb = int(line.split()[1])
                        mem_gb = mem_kb / (1024 * 1024)

                        if mem_gb < 2:
                            return ComputeTier.FORTRESS_LITE
                        elif mem_gb < 6:
                            return ComputeTier.FORTRESS_STANDARD
                        else:
                            return ComputeTier.FORTRESS_STANDARD
        except Exception:
            pass

        return ComputeTier.FORTRESS_LITE

    def process_attack(
        self,
        attack_type: str,
        source_ip: Optional[str] = None,
        source_data: Optional[Dict[str, Any]] = None,
        auto_respond: bool = True
    ) -> Dict[str, Any]:
        """
        Process detected attack event.

        Args:
            attack_type: Type of attack detected
            source_ip: Source IP (will be anonymized)
            source_data: Additional attack context
            auto_respond: Whether to generate and execute response

        Returns:
            Dict with prediction, IoC, and strategy
        """
        self._events_processed += 1

        # Add to predictor sequence
        self.predictor.add_event(attack_type)

        # Get prediction
        prediction = self.predictor.predict()

        result = {
            "prediction": prediction.to_dict(),
            "ioc": None,
            "strategy": None,
            "offloaded_to_nexus": False,
        }

        # Check if task needs Nexus
        task = self.predictor.get_compute_task()
        if self.enable_nexus_offload and task.requires_nexus():
            nexus_result = self._offload_to_nexus(prediction, source_ip, source_data)
            if nexus_result:
                result["offloaded_to_nexus"] = True
                result["nexus_task_id"] = nexus_result.get("task_id")
                self._nexus_offloads += 1
                return result

        # Generate IoC
        ioc = self.ioc_generator.from_prediction(
            prediction,
            source_ip=source_ip,
            source_data=source_data
        )
        self._iocs_generated += 1
        result["ioc"] = ioc.to_dict()

        # Get defense strategy
        if auto_respond:
            strategy = self.orchestrator.consult(
                ioc,
                prediction,
                use_ai=self.enable_ai_consultation
            )
            self._strategies_created += 1
            result["strategy"] = strategy.to_dict()

            # Notify handlers
            for handler in self._response_handlers:
                try:
                    handler(strategy)
                except Exception as e:
                    print(f"Handler error: {e}")

        return result

    def get_prediction(self) -> ThreatPrediction:
        """Get current threat prediction"""
        return self.predictor.predict()

    def get_aggregated_iocs(self, minutes: int = 60) -> List[IoC]:
        """Get aggregated IoCs from recent window"""
        return self.ioc_generator.aggregate_iocs(time_window_minutes=minutes)

    def get_defense_strategy(
        self,
        ioc: IoC,
        prediction: Optional[ThreatPrediction] = None
    ) -> DefenseStrategy:
        """Get defense strategy for specific IoC"""
        return self.orchestrator.consult(
            ioc,
            prediction,
            use_ai=self.enable_ai_consultation
        )

    def execute_defense(
        self,
        strategy: DefenseStrategy,
        ioc: IoC
    ) -> bool:
        """Execute defense strategy via n8n"""
        return self.orchestrator.trigger_n8n_workflow(strategy, ioc)

    def register_response_handler(
        self,
        handler: Callable[[DefenseStrategy], None]
    ):
        """Register handler for defense responses"""
        self._response_handlers.append(handler)

    def _offload_to_nexus(
        self,
        prediction: ThreatPrediction,
        source_ip: Optional[str],
        source_data: Optional[Dict]
    ) -> Optional[Dict]:
        """Offload complex task to Nexus node"""
        # Find available Nexus
        task = ComputeTask(
            task_type="deep_analysis",
            estimated_memory_mb=4096,
            estimated_gpu_required=True,
            estimated_duration_sec=120,
            input_data={
                "prediction": prediction.to_dict(),
                "source_ip": source_ip,
                "source_data": source_data,
            }
        )

        task = self.evaluator.route_task(task)

        if task.routed_to_node and task.routed_to_node != "local":
            # TODO: Implement actual Nexus communication
            # For now, return the task info
            return {
                "task_id": task.task_id,
                "routed_to": task.routed_to_node,
                "tier": task.assigned_tier.value if task.assigned_tier else None,
            }

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get integration statistics"""
        return {
            "compute_tier": self.compute_tier.value,
            "events_processed": self._events_processed,
            "iocs_generated": self._iocs_generated,
            "strategies_created": self._strategies_created,
            "nexus_offloads": self._nexus_offloads,
            "predictor": self.predictor.get_stats(),
            "orchestrator": self.orchestrator.get_stats(),
            "routing": self.evaluator.get_routing_stats(),
        }

    def _load_state(self):
        """Load saved predictor state"""
        try:
            self.predictor.load_statistics()
        except Exception:
            pass

    def save_state(self):
        """Save current state for persistence"""
        try:
            self.predictor.save_statistics()
            self.ioc_generator.save_iocs(
                self.ioc_generator.aggregate_iocs(60),
                "recent_iocs.json"
            )
        except Exception as e:
            print(f"Error saving state: {e}")


# Singleton instance for Fortress
_fortress_ai: Optional[FortressAIIntegration] = None


def get_fortress_ai() -> FortressAIIntegration:
    """Get or create Fortress AI integration instance"""
    global _fortress_ai
    if _fortress_ai is None:
        _fortress_ai = FortressAIIntegration()
    return _fortress_ai


def process_threat_event(
    attack_type: str,
    source_ip: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Convenience function to process threat event.

    Called by QSecBit agent when threats are detected.
    """
    ai = get_fortress_ai()
    return ai.process_attack(attack_type, source_ip, kwargs)


# Example response handler for QSecBit
def qsecbit_response_handler(strategy: DefenseStrategy):
    """Handle defense strategy for QSecBit integration"""
    if strategy.primary_action == DefenseAction.BLOCK_IP:
        # Would call XDP/iptables
        print(f"[QSecBit] Block IP: {strategy.action_params}")
    elif strategy.primary_action == DefenseAction.RATE_LIMIT:
        print(f"[QSecBit] Rate limit: {strategy.action_params}")
    elif strategy.primary_action == DefenseAction.ALERT:
        print(f"[QSecBit] Alert: {strategy.reasoning}")


# Register default handler
if AI_VS_AI_AVAILABLE:
    try:
        ai = get_fortress_ai()
        ai.register_response_handler(qsecbit_response_handler)
    except Exception:
        pass
