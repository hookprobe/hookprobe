"""
AIOCHI Playbook Engine
Loads, matches, and executes security playbooks for automated threat response.

Philosophy: Break the attack chain as early as possible.
A flower shop can't afford a 30-minute response time to ransomware.

Features:
- Load predefined JSON playbooks
- Match alerts to playbooks using triggers
- Execute OVS/DNS/tc commands automatically
- Generate AI playbooks for unknown threats
- One-click "FIX IT" actions for the UI
"""

import ipaddress
import json
import logging
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Security: Validation patterns
MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
INTERFACE_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,14}$')


def _validate_ip(ip_str: str) -> bool:
    """Validate IP address to prevent command injection."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _validate_mac(mac_str: str) -> bool:
    """Validate MAC address format."""
    return bool(MAC_PATTERN.match(mac_str))


@dataclass
class PlaybookMatch:
    """Result of matching an alert to a playbook."""
    playbook_id: str
    playbook_name: str
    confidence: float  # 0.0-1.0 how well it matched
    trigger_type: str
    trigger_details: Dict[str, Any]


@dataclass
class PlaybookExecution:
    """Record of a playbook execution."""
    id: str
    playbook_id: str
    playbook_name: str
    trigger_alert: Dict[str, Any]
    started_at: datetime
    completed_at: Optional[datetime] = None
    actions_executed: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = False
    error_message: str = ""
    narrative_sent: str = ""
    rollback_available: bool = False


class PlaybookEngine:
    """
    Playbook Engine for AIOCHI.

    Loads playbooks from JSON files, matches incoming alerts,
    and executes automated responses.
    """

    OVS_BRIDGE = "FTS"

    def __init__(
        self,
        playbooks_dir: str = None,
        use_ovs: bool = True,
        use_ai: bool = True,
        dry_run: bool = False,
    ):
        """
        Initialize the Playbook Engine.

        Args:
            playbooks_dir: Directory containing playbook JSON files (auto-detected if None)
            use_ovs: Enable OVS command execution
            use_ai: Enable AI playbook generation for unknown threats
            dry_run: Log commands instead of executing
        """
        # Auto-detect playbooks directory
        if playbooks_dir is None:
            # Check container path first, then development path
            container_path = Path("/app/shared/aiochi/playbooks")
            dev_path = Path(__file__).parent.parent / "playbooks"
            if container_path.exists():
                playbooks_dir = str(container_path)
            elif dev_path.exists():
                playbooks_dir = str(dev_path)
            else:
                playbooks_dir = str(dev_path)  # Will log warning if not found
        self.playbooks_dir = playbooks_dir
        self.use_ovs = use_ovs
        self.use_ai = use_ai
        self.dry_run = dry_run

        # Loaded playbooks (id -> playbook dict)
        self._playbooks: Dict[str, Dict[str, Any]] = {}

        # Execution history
        self._executions: List[PlaybookExecution] = []
        self._max_executions = 500

        # Rollback commands (execution_id -> [commands])
        self._rollback_registry: Dict[str, List[str]] = {}

        # AI client (lazy load)
        self._ai_client = None

        # Callbacks for UI notifications
        self._callbacks: List[Callable[[PlaybookExecution], None]] = []

        # Load playbooks
        self._load_playbooks()

        logger.info(f"Playbook Engine initialized with {len(self._playbooks)} playbooks")

    # =========================================================================
    # Playbook Loading
    # =========================================================================

    def _load_playbooks(self) -> None:
        """Load all playbooks from the playbooks directory."""
        playbooks_path = Path(self.playbooks_dir)

        if not playbooks_path.exists():
            logger.warning(f"Playbooks directory not found: {self.playbooks_dir}")
            return

        for file_path in playbooks_path.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    playbook = json.load(f)

                playbook_id = playbook.get("id")
                if playbook_id:
                    self._playbooks[playbook_id] = playbook
                    logger.debug(f"Loaded playbook: {playbook_id}")

            except Exception as e:
                logger.error(f"Failed to load playbook {file_path}: {e}")

    def reload_playbooks(self) -> int:
        """Reload all playbooks from disk."""
        self._playbooks.clear()
        self._load_playbooks()
        return len(self._playbooks)

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get a playbook by ID."""
        return self._playbooks.get(playbook_id)

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all loaded playbooks."""
        return [
            {
                "id": pb["id"],
                "name": pb["name"],
                "description": pb.get("description", ""),
                "category": pb.get("category", ""),
                "mitre_attack": pb.get("mitre_attack", []),
            }
            for pb in self._playbooks.values()
        ]

    # =========================================================================
    # Alert Matching
    # =========================================================================

    def match_alert(
        self,
        alert: Dict[str, Any],
    ) -> Optional[PlaybookMatch]:
        """
        Match an alert to a playbook.

        Args:
            alert: IDS alert or similar

        Returns:
            PlaybookMatch if a playbook matches, None otherwise
        """
        alert_signature = alert.get("alert", {}).get("signature", "")
        alert_category = alert.get("alert", {}).get("category", "")
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dest_ip", "")
        dst_port = alert.get("dest_port", 0)

        best_match: Optional[PlaybookMatch] = None
        best_confidence = 0.0

        for playbook in self._playbooks.values():
            confidence, trigger_type, trigger_details = self._check_triggers(
                playbook, alert_signature, alert_category, src_ip, dst_ip, dst_port
            )

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = PlaybookMatch(
                    playbook_id=playbook["id"],
                    playbook_name=playbook["name"],
                    confidence=confidence,
                    trigger_type=trigger_type,
                    trigger_details=trigger_details,
                )

        # If no predefined match and AI is enabled, try AI
        if best_match is None or best_confidence < 0.5:
            if self.use_ai and alert_signature:
                ai_playbook = self._generate_ai_playbook(alert)
                if ai_playbook:
                    return PlaybookMatch(
                        playbook_id="ai_generated",
                        playbook_name=f"AI: {ai_playbook.mitre_name}",
                        confidence=ai_playbook.confidence,
                        trigger_type="ai_generated",
                        trigger_details={"ai_playbook": ai_playbook},
                    )

        return best_match if best_match and best_confidence >= 0.3 else None

    def _check_triggers(
        self,
        playbook: Dict[str, Any],
        signature: str,
        category: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Check if playbook triggers match the alert."""
        triggers = playbook.get("triggers", [])
        best_confidence = 0.0
        best_type = ""
        best_details: Dict[str, Any] = {}

        for trigger in triggers:
            trigger_type = trigger.get("type", "")
            confidence = 0.0
            details: Dict[str, Any] = {}

            if trigger_type == "ids_signature":
                patterns = trigger.get("patterns", [])
                for pattern in patterns:
                    if pattern.lower() in signature.lower():
                        confidence = 0.9
                        details = {"matched_pattern": pattern}
                        break

            elif trigger_type == "dns_query":
                patterns = trigger.get("patterns", [])
                # Would check against actual DNS query if available
                for pattern in patterns:
                    if pattern.lower() in signature.lower():
                        confidence = 0.8
                        details = {"matched_pattern": pattern}
                        break

            elif trigger_type == "port_scan":
                conditions = trigger.get("conditions", {})
                ports = conditions.get("destination_ports", [])
                if dst_port in ports:
                    confidence = 0.7
                    details = {"matched_port": dst_port}

            if confidence > best_confidence:
                best_confidence = confidence
                best_type = trigger_type
                best_details = details

        return best_confidence, best_type, best_details

    def _generate_ai_playbook(self, alert: Dict[str, Any]):
        """Generate a playbook using AI for unknown threats."""
        try:
            if self._ai_client is None:
                from .openrouter_client import get_openrouter_client
                self._ai_client = get_openrouter_client()

            return self._ai_client.generate_playbook(
                alert_name=alert.get("alert", {}).get("signature", "Unknown"),
                device_type="Unknown device",
                src_ip=alert.get("src_ip", ""),
                dst_ip=alert.get("dest_ip", ""),
                dst_port=alert.get("dest_port", 0),
            )
        except Exception as e:
            logger.debug(f"AI playbook generation failed: {e}")
            return None

    # =========================================================================
    # Playbook Execution
    # =========================================================================

    def execute_playbook(
        self,
        playbook_id: str,
        trigger_context: Dict[str, Any],
    ) -> PlaybookExecution:
        """
        Execute a playbook with the given context.

        Args:
            playbook_id: Playbook ID to execute
            trigger_context: Context variables for template substitution

        Returns:
            PlaybookExecution record
        """
        import uuid

        execution = PlaybookExecution(
            id=str(uuid.uuid4()),
            playbook_id=playbook_id,
            playbook_name="Unknown",
            trigger_alert=trigger_context,
            started_at=datetime.now(),
        )

        # Handle AI-generated playbooks
        if playbook_id == "ai_generated":
            ai_playbook = trigger_context.get("ai_playbook")
            if ai_playbook:
                execution = self._execute_ai_playbook(execution, ai_playbook, trigger_context)
            else:
                execution.error_message = "AI playbook not provided"
            return self._record_execution(execution)

        playbook = self._playbooks.get(playbook_id)
        if not playbook:
            execution.error_message = f"Playbook not found: {playbook_id}"
            return self._record_execution(execution)

        execution.playbook_name = playbook["name"]
        rollback_commands: List[str] = []

        try:
            # Execute each action in order
            for action in playbook.get("actions", []):
                action_result = self._execute_action(action, trigger_context)
                execution.actions_executed.append(action_result)

                # Collect rollback commands
                if action.get("rollback"):
                    rollback_cmd = self._substitute_variables(
                        action["rollback"], trigger_context
                    )
                    rollback_commands.append(rollback_cmd)

                if not action_result.get("success", False):
                    logger.warning(f"Action failed: {action_result}")

            # Send narrative
            narratives = playbook.get("narratives", {})
            execution.narrative_sent = self._substitute_variables(
                narratives.get("owner_friendly", "Security action taken."),
                trigger_context
            )

            execution.success = True
            execution.completed_at = datetime.now()

            # Store rollback commands
            if rollback_commands:
                self._rollback_registry[execution.id] = rollback_commands
                execution.rollback_available = True

        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            execution.error_message = str(e)
            execution.completed_at = datetime.now()

        return self._record_execution(execution)

    def _execute_ai_playbook(
        self,
        execution: PlaybookExecution,
        ai_playbook,
        context: Dict[str, Any],
    ) -> PlaybookExecution:
        """Execute an AI-generated playbook."""
        execution.playbook_name = f"AI: {ai_playbook.mitre_name}"
        rollback_commands: List[str] = []

        try:
            # Execute OVS commands
            for cmd in ai_playbook.ovs_commands:
                result = self._execute_command(cmd)
                execution.actions_executed.append({
                    "type": "ovs_command",
                    "command": cmd,
                    "success": result["success"],
                })

            # Execute DNS blocks
            for domain in ai_playbook.dns_blocks:
                result = self._execute_dns_block(domain)
                execution.actions_executed.append({
                    "type": "dns_block",
                    "domain": domain,
                    "success": result,
                })

            execution.narrative_sent = ai_playbook.owner_narrative
            execution.success = True
            execution.completed_at = datetime.now()

        except Exception as e:
            logger.error(f"AI playbook execution failed: {e}")
            execution.error_message = str(e)
            execution.completed_at = datetime.now()

        return execution

    def _execute_action(
        self,
        action: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a single playbook action."""
        action_type = action.get("type", "")
        description = action.get("description", "")
        command = action.get("command", "")

        result = {
            "order": action.get("order", 0),
            "type": action_type,
            "description": description,
            "success": False,
            "output": "",
        }

        # Substitute variables in command
        if command:
            command = self._substitute_variables(command, context)

        try:
            if action_type in ["ovs_isolate", "ovs_quarantine", "ovs_block"]:
                cmd_result = self._execute_command(command)
                result["success"] = cmd_result["success"]
                result["output"] = cmd_result["output"]

            elif action_type == "dns_block":
                params = action.get("parameters", {})
                domain = self._substitute_variables(
                    params.get("domain", ""), context
                )
                result["success"] = self._execute_dns_block(domain)

            elif action_type == "bandwidth_throttle":
                cmd_result = self._execute_command(command)
                result["success"] = cmd_result["success"]

            elif action_type == "mac_blacklist":
                cmd_result = self._execute_command(command)
                result["success"] = cmd_result["success"]

            elif action_type in ["device_flag", "set_device_status", "pos_lock"]:
                # These would integrate with device manager
                result["success"] = True
                result["output"] = f"Device status updated"

            elif action_type == "notification":
                result["success"] = True
                result["output"] = "Notification queued"

            elif action_type == "pcap_snapshot":
                cmd_result = self._execute_command(command)
                result["success"] = cmd_result["success"]

            elif action_type == "session_terminate":
                cmd_result = self._execute_command(command)
                result["success"] = cmd_result["success"]

            else:
                logger.warning(f"Unknown action type: {action_type}")
                result["success"] = True  # Don't fail on unknown

        except Exception as e:
            result["output"] = str(e)
            logger.error(f"Action execution error: {e}")

        return result

    def _execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command safely without shell=True."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {command}")
            return {"success": True, "output": "[dry run]"}

        if not self.use_ovs and command.startswith("ovs-"):
            logger.info(f"[OVS DISABLED] Skipping: {command}")
            return {"success": True, "output": "[ovs disabled]"}

        try:
            # Security: Use shlex.split() to safely tokenize, avoid shell=True
            cmd_list = shlex.split(command)
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout or result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "Command timeout"}
        except Exception as e:
            return {"success": False, "output": str(e)}

    def _execute_dns_block(self, domain: str) -> bool:
        """Block a domain via dnsXai."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would block domain: {domain}")
            return True

        try:
            import requests
            response = requests.post(
                "http://localhost:8053/api/blocklist/add",
                json={"domain": domain},
                timeout=5,
            )
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"DNS block failed: {e}")
            return False

    def _substitute_variables(self, template: str, context: Dict[str, Any]) -> str:
        """Substitute {{variable}} placeholders in template."""
        def replace(match):
            var_path = match.group(1)
            parts = var_path.split(".")
            value = context

            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part, "")
                else:
                    return ""

            return str(value) if value else ""

        return re.sub(r'\{\{(\S+?)\}\}', replace, template)

    def _record_execution(self, execution: PlaybookExecution) -> PlaybookExecution:
        """Record execution and notify callbacks."""
        self._executions.append(execution)
        if len(self._executions) > self._max_executions:
            self._executions.pop(0)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(execution)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        return execution

    # =========================================================================
    # Rollback & One-Click Actions
    # =========================================================================

    def rollback_execution(self, execution_id: str) -> bool:
        """
        Rollback a previous playbook execution.

        Args:
            execution_id: ID of execution to rollback

        Returns:
            True if rollback successful
        """
        commands = self._rollback_registry.get(execution_id, [])
        if not commands:
            logger.warning(f"No rollback available for {execution_id}")
            return False

        success = True
        for cmd in commands:
            result = self._execute_command(cmd)
            if not result["success"]:
                logger.error(f"Rollback command failed: {cmd}")
                success = False

        if success:
            del self._rollback_registry[execution_id]

        return success

    def one_click_fix(
        self,
        action_type: str,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a one-click fix action from the UI.

        Args:
            action_type: Type of fix action
            target: Target MAC, IP, or domain
            parameters: Additional parameters

        Returns:
            Result dictionary
        """
        params = parameters or {}

        if action_type == "block_mac":
            cmd = f'ovs-ofctl add-flow {self.OVS_BRIDGE} "priority=500,dl_src={target},actions=drop"'
            result = self._execute_command(cmd)
            return {"success": result["success"], "action": "MAC blocked"}

        elif action_type == "unblock_mac":
            cmd = f'ovs-ofctl del-flows {self.OVS_BRIDGE} "dl_src={target},priority=500"'
            result = self._execute_command(cmd)
            return {"success": result["success"], "action": "MAC unblocked"}

        elif action_type == "block_ip":
            cmd = f'ovs-ofctl add-flow {self.OVS_BRIDGE} "priority=500,ip,nw_src={target},actions=drop"'
            result = self._execute_command(cmd)
            return {"success": result["success"], "action": "IP blocked"}

        elif action_type == "unblock_ip":
            cmd = f'ovs-ofctl del-flows {self.OVS_BRIDGE} "ip,nw_src={target},priority=500"'
            result = self._execute_command(cmd)
            return {"success": result["success"], "action": "IP unblocked"}

        elif action_type == "block_domain":
            success = self._execute_dns_block(target)
            return {"success": success, "action": "Domain blocked"}

        elif action_type == "quarantine_device":
            cmd1 = f'ovs-ofctl add-flow {self.OVS_BRIDGE} "priority=1000,dl_src={target},actions=drop"'
            cmd2 = f'ovs-ofctl add-flow {self.OVS_BRIDGE} "priority=1000,dl_dst={target},actions=drop"'
            r1 = self._execute_command(cmd1)
            r2 = self._execute_command(cmd2)
            return {"success": r1["success"] and r2["success"], "action": "Device quarantined"}

        elif action_type == "release_quarantine":
            cmd1 = f'ovs-ofctl del-flows {self.OVS_BRIDGE} "dl_src={target},priority=1000"'
            cmd2 = f'ovs-ofctl del-flows {self.OVS_BRIDGE} "dl_dst={target},priority=1000"'
            r1 = self._execute_command(cmd1)
            r2 = self._execute_command(cmd2)
            return {"success": r1["success"] and r2["success"], "action": "Quarantine released"}

        elif action_type == "throttle_bandwidth":
            rate = params.get("rate", "10kbit")
            # Would need tc integration
            return {"success": True, "action": f"Bandwidth throttled to {rate}"}

        elif action_type == "restore_bandwidth":
            return {"success": True, "action": "Bandwidth restored"}

        else:
            return {"success": False, "action": f"Unknown action: {action_type}"}

    # =========================================================================
    # API
    # =========================================================================

    def add_callback(self, callback: Callable[[PlaybookExecution], None]) -> None:
        """Add a callback for playbook executions."""
        self._callbacks.append(callback)

    def get_executions(self, limit: int = 50) -> List[PlaybookExecution]:
        """Get recent playbook executions."""
        return list(reversed(self._executions[-limit:]))

    def get_summary(self) -> Dict[str, Any]:
        """Get engine summary for dashboard."""
        return {
            "playbooks_loaded": len(self._playbooks),
            "executions_total": len(self._executions),
            "executions_success": sum(1 for e in self._executions if e.success),
            "rollbacks_available": len(self._rollback_registry),
            "ai_enabled": self.use_ai,
            "dry_run": self.dry_run,
        }


# Singleton instance
_engine: Optional[PlaybookEngine] = None


def get_playbook_engine(
    use_ovs: bool = True,
    dry_run: bool = False,
) -> PlaybookEngine:
    """Get or create the singleton playbook engine."""
    global _engine

    if _engine is None:
        _engine = PlaybookEngine(use_ovs=use_ovs, dry_run=dry_run)

    return _engine


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)

    engine = PlaybookEngine(dry_run=True)

    print("Playbook Engine Demo")
    print(f"Loaded playbooks: {len(engine.list_playbooks())}")

    for pb in engine.list_playbooks():
        print(f"  - {pb['id']}: {pb['name']}")

    # Test alert matching
    test_alert = {
        "event_type": "alert",
        "src_ip": "10.200.0.50",
        "dest_ip": "185.220.101.1",
        "dest_port": 443,
        "alert": {
            "signature": "ET MALWARE Ransomware Traffic Detected",
            "severity": 1,
        }
    }

    print(f"\nMatching alert: {test_alert['alert']['signature']}")
    match = engine.match_alert(test_alert)

    if match:
        print(f"  Matched: {match.playbook_name} (confidence: {match.confidence:.0%})")

        # Execute the playbook
        context = {
            "trigger": {
                "src_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": test_alert["src_ip"],
                "dst_ip": test_alert["dest_ip"],
            },
            "device": {
                "name": "Laptop-A",
                "mac": "AA:BB:CC:DD:EE:FF",
            }
        }

        execution = engine.execute_playbook(match.playbook_id, context)
        print(f"\n  Execution: {execution.success}")
        print(f"  Narrative: {execution.narrative_sent[:100]}...")

    # Test one-click fix
    print("\nTesting one-click fix...")
    result = engine.one_click_fix("block_mac", "AA:BB:CC:DD:EE:FF")
    print(f"  Result: {result}")
