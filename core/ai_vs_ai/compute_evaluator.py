"""
Compute Evaluator

Evaluates compute requirements and routes tasks between
Fortress (lite) and Nexus (advanced) based on resource needs.

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import os
import json
import time
import socket
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from .models import ComputeTask, ComputeTier


# Resource thresholds for tier routing
TIER_THRESHOLDS = {
    ComputeTier.FORTRESS_LITE: {
        "max_memory_mb": 1024,
        "max_cpu_cores": 1.0,
        "max_duration_sec": 30,
        "gpu_support": False,
    },
    ComputeTier.FORTRESS_STANDARD: {
        "max_memory_mb": 2048,
        "max_cpu_cores": 2.0,
        "max_duration_sec": 60,
        "gpu_support": False,
    },
    ComputeTier.NEXUS_STANDARD: {
        "max_memory_mb": 8192,
        "max_cpu_cores": 4.0,
        "max_duration_sec": 300,
        "gpu_support": True,
    },
    ComputeTier.NEXUS_ADVANCED: {
        "max_memory_mb": 32768,
        "max_cpu_cores": 8.0,
        "max_duration_sec": 3600,
        "gpu_support": True,
    },
    ComputeTier.MSSP_CLOUD: {
        "max_memory_mb": float('inf'),
        "max_cpu_cores": float('inf'),
        "max_duration_sec": float('inf'),
        "gpu_support": True,
    },
}


@dataclass
class SystemResources:
    """Current system resource availability"""
    total_memory_mb: int
    available_memory_mb: int
    cpu_count: int
    cpu_load_percent: float
    gpu_available: bool
    gpu_memory_mb: int
    disk_free_gb: float


@dataclass
class NexusNode:
    """Remote Nexus node for task offloading"""
    node_id: str
    address: str
    port: int
    tier: ComputeTier
    available: bool
    last_seen: datetime
    resources: Optional[SystemResources] = None


class ComputeEvaluator:
    """
    Evaluate and route compute tasks between Fortress and Nexus.

    Responsibilities:
    1. Monitor local system resources
    2. Maintain list of available Nexus nodes
    3. Route tasks to appropriate tier
    4. Track task execution and performance
    """

    def __init__(
        self,
        local_tier: ComputeTier = ComputeTier.FORTRESS_STANDARD,
        nexus_registry_path: Optional[Path] = None
    ):
        self.local_tier = local_tier
        self.nexus_registry_path = nexus_registry_path or Path(
            "/etc/hookprobe/nexus_nodes.json"
        )

        # Known Nexus nodes
        self._nexus_nodes: Dict[str, NexusNode] = {}

        # Task routing history
        self._routing_history: List[Dict] = []
        self._max_history = 1000

        # Load Nexus registry
        self._load_nexus_registry()

    def evaluate_task(self, task: ComputeTask) -> Tuple[ComputeTier, Optional[str]]:
        """
        Evaluate task requirements and determine routing.

        Args:
            task: ComputeTask to evaluate

        Returns:
            Tuple of (assigned tier, node_id if remote)
        """
        # Check if task can run locally
        if self._can_run_locally(task):
            return self.local_tier, None

        # Check if we need to route to Nexus
        if task.requires_nexus():
            nexus_node = self._find_available_nexus(task)
            if nexus_node:
                return nexus_node.tier, nexus_node.node_id
            else:
                # No Nexus available, try to run locally anyway
                print(f"Warning: Task requires Nexus but none available")
                return self.local_tier, None

        return self.local_tier, None

    def route_task(self, task: ComputeTask) -> ComputeTask:
        """
        Route task to appropriate compute tier.

        Args:
            task: Task to route

        Returns:
            Task with assigned tier and node
        """
        tier, node_id = self.evaluate_task(task)
        task.assigned_tier = tier
        task.routed_to_node = node_id or "local"

        # Record routing decision
        self._record_routing(task)

        return task

    def _can_run_locally(self, task: ComputeTask) -> bool:
        """Check if task can run on local system"""
        local_thresholds = TIER_THRESHOLDS.get(self.local_tier, {})

        # Check memory
        if task.estimated_memory_mb > local_thresholds.get("max_memory_mb", 0):
            return False

        # Check CPU
        if task.estimated_cpu_cores > local_thresholds.get("max_cpu_cores", 0):
            return False

        # Check duration
        if task.estimated_duration_sec > local_thresholds.get("max_duration_sec", 0):
            return False

        # Check GPU
        if task.estimated_gpu_required and not local_thresholds.get("gpu_support", False):
            return False

        # Check current system load
        resources = self.get_local_resources()
        if resources.available_memory_mb < task.estimated_memory_mb * 1.5:
            return False
        if resources.cpu_load_percent > 80:
            return False

        return True

    def _find_available_nexus(self, task: ComputeTask) -> Optional[NexusNode]:
        """Find available Nexus node for task"""
        # Refresh node status
        self._refresh_nexus_status()

        # Filter available nodes
        available_nodes = [
            node for node in self._nexus_nodes.values()
            if node.available
        ]

        if not available_nodes:
            return None

        # Sort by capability (prefer higher tiers for demanding tasks)
        tier_priority = {
            ComputeTier.NEXUS_STANDARD: 1,
            ComputeTier.NEXUS_ADVANCED: 2,
            ComputeTier.MSSP_CLOUD: 3,
        }

        available_nodes.sort(
            key=lambda n: tier_priority.get(n.tier, 0),
            reverse=task.estimated_gpu_required
        )

        # Find node that can handle the task
        for node in available_nodes:
            thresholds = TIER_THRESHOLDS.get(node.tier, {})

            if (task.estimated_memory_mb <= thresholds.get("max_memory_mb", 0) and
                task.estimated_duration_sec <= thresholds.get("max_duration_sec", 0) and
                (not task.estimated_gpu_required or thresholds.get("gpu_support", False))):
                return node

        return None

    def get_local_resources(self) -> SystemResources:
        """Get current local system resources"""
        try:
            # Memory info
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip().split()[0]
                        meminfo[key] = int(value)

            total_memory_mb = meminfo.get('MemTotal', 0) // 1024
            available_memory_mb = meminfo.get('MemAvailable', 0) // 1024

            # CPU info
            cpu_count = os.cpu_count() or 1

            # CPU load
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
                cpu_load_percent = min(100, (load / cpu_count) * 100)

            # GPU detection
            gpu_available = self._detect_gpu()
            gpu_memory_mb = self._get_gpu_memory() if gpu_available else 0

            # Disk space
            statvfs = os.statvfs('/')
            disk_free_gb = (statvfs.f_frsize * statvfs.f_bavail) / (1024 ** 3)

            return SystemResources(
                total_memory_mb=total_memory_mb,
                available_memory_mb=available_memory_mb,
                cpu_count=cpu_count,
                cpu_load_percent=cpu_load_percent,
                gpu_available=gpu_available,
                gpu_memory_mb=gpu_memory_mb,
                disk_free_gb=disk_free_gb,
            )

        except Exception as e:
            print(f"Error getting system resources: {e}")
            # Return conservative defaults
            return SystemResources(
                total_memory_mb=2048,
                available_memory_mb=1024,
                cpu_count=2,
                cpu_load_percent=50,
                gpu_available=False,
                gpu_memory_mb=0,
                disk_free_gb=10,
            )

    def _detect_gpu(self) -> bool:
        """Detect if GPU is available"""
        try:
            # Check for NVIDIA GPU
            result = subprocess.run(
                ['nvidia-smi', '--query-gpu=name', '--format=csv,noheader'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_gpu_memory(self) -> int:
        """Get GPU memory in MB"""
        try:
            result = subprocess.run(
                ['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
        except Exception:
            pass
        return 0

    def register_nexus_node(
        self,
        node_id: str,
        address: str,
        port: int = 8765,
        tier: ComputeTier = ComputeTier.NEXUS_STANDARD
    ):
        """Register a Nexus node"""
        node = NexusNode(
            node_id=node_id,
            address=address,
            port=port,
            tier=tier,
            available=True,
            last_seen=datetime.now(),
        )
        self._nexus_nodes[node_id] = node
        self._save_nexus_registry()

    def unregister_nexus_node(self, node_id: str):
        """Unregister a Nexus node"""
        if node_id in self._nexus_nodes:
            del self._nexus_nodes[node_id]
            self._save_nexus_registry()

    def _refresh_nexus_status(self):
        """Check status of all Nexus nodes"""
        for node_id, node in self._nexus_nodes.items():
            try:
                # Simple TCP check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((node.address, node.port))
                sock.close()

                node.available = (result == 0)
                if node.available:
                    node.last_seen = datetime.now()

            except Exception:
                node.available = False

    def _load_nexus_registry(self):
        """Load Nexus node registry from file"""
        try:
            if self.nexus_registry_path.exists():
                with open(self.nexus_registry_path, 'r') as f:
                    data = json.load(f)
                    for node_data in data.get('nodes', []):
                        node = NexusNode(
                            node_id=node_data['node_id'],
                            address=node_data['address'],
                            port=node_data.get('port', 8765),
                            tier=ComputeTier(node_data.get('tier', 'nexus_std')),
                            available=False,
                            last_seen=datetime.fromisoformat(
                                node_data.get('last_seen', datetime.now().isoformat())
                            ),
                        )
                        self._nexus_nodes[node.node_id] = node
        except Exception as e:
            print(f"Error loading Nexus registry: {e}")

    def _save_nexus_registry(self):
        """Save Nexus node registry to file"""
        try:
            self.nexus_registry_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                'nodes': [
                    {
                        'node_id': node.node_id,
                        'address': node.address,
                        'port': node.port,
                        'tier': node.tier.value,
                        'last_seen': node.last_seen.isoformat(),
                    }
                    for node in self._nexus_nodes.values()
                ],
                'updated': datetime.now().isoformat(),
            }

            with open(self.nexus_registry_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"Error saving Nexus registry: {e}")

    def _record_routing(self, task: ComputeTask):
        """Record routing decision for analytics"""
        record = {
            'task_id': task.task_id,
            'task_type': task.task_type,
            'assigned_tier': task.assigned_tier.value if task.assigned_tier else None,
            'routed_to': task.routed_to_node,
            'timestamp': datetime.now().isoformat(),
            'requirements': {
                'memory_mb': task.estimated_memory_mb,
                'cpu_cores': task.estimated_cpu_cores,
                'gpu_required': task.estimated_gpu_required,
                'duration_sec': task.estimated_duration_sec,
            }
        }

        self._routing_history.append(record)

        # Trim history
        if len(self._routing_history) > self._max_history:
            self._routing_history = self._routing_history[-self._max_history:]

    def get_routing_stats(self) -> Dict[str, Any]:
        """Get routing statistics"""
        if not self._routing_history:
            return {
                "total_tasks": 0,
                "local_tasks": 0,
                "remote_tasks": 0,
                "tier_distribution": {},
            }

        tier_counts = {}
        local_count = 0
        remote_count = 0

        for record in self._routing_history:
            tier = record.get('assigned_tier')
            if tier:
                tier_counts[tier] = tier_counts.get(tier, 0) + 1

            if record.get('routed_to') == 'local':
                local_count += 1
            else:
                remote_count += 1

        return {
            "total_tasks": len(self._routing_history),
            "local_tasks": local_count,
            "remote_tasks": remote_count,
            "local_percentage": local_count / len(self._routing_history) * 100,
            "tier_distribution": tier_counts,
            "nexus_nodes_registered": len(self._nexus_nodes),
            "nexus_nodes_available": sum(1 for n in self._nexus_nodes.values() if n.available),
        }

    def get_recommendation(self, task: ComputeTask) -> Dict[str, Any]:
        """
        Get detailed routing recommendation for task.

        Useful for UI/API to show why a task was routed to a specific tier.
        """
        resources = self.get_local_resources()
        tier, node_id = self.evaluate_task(task)

        reasons = []

        if task.estimated_memory_mb > resources.available_memory_mb * 0.7:
            reasons.append(f"Memory: {task.estimated_memory_mb}MB needed, {resources.available_memory_mb}MB available")

        if task.estimated_gpu_required and not resources.gpu_available:
            reasons.append("GPU required but not available locally")

        if resources.cpu_load_percent > 70:
            reasons.append(f"High CPU load: {resources.cpu_load_percent:.0f}%")

        return {
            "recommended_tier": tier.value,
            "recommended_node": node_id or "local",
            "can_run_locally": task.can_run_on_fortress(),
            "requires_nexus": task.requires_nexus(),
            "reasons": reasons,
            "local_resources": {
                "available_memory_mb": resources.available_memory_mb,
                "cpu_load_percent": resources.cpu_load_percent,
                "gpu_available": resources.gpu_available,
            }
        }


def create_evaluator_for_product(product: str) -> ComputeEvaluator:
    """
    Factory function to create evaluator for product.

    Args:
        product: Product name (fortress, nexus)

    Returns:
        Configured ComputeEvaluator
    """
    if product.lower() == "fortress":
        # Detect if this is lite or standard Fortress
        try:
            resources = ComputeEvaluator().get_local_resources()
            if resources.total_memory_mb < 3000:  # Less than 3GB
                tier = ComputeTier.FORTRESS_LITE
            else:
                tier = ComputeTier.FORTRESS_STANDARD
        except Exception:
            tier = ComputeTier.FORTRESS_LITE

        return ComputeEvaluator(local_tier=tier)

    elif product.lower() == "nexus":
        return ComputeEvaluator(local_tier=ComputeTier.NEXUS_ADVANCED)

    else:
        return ComputeEvaluator(local_tier=ComputeTier.FORTRESS_LITE)
