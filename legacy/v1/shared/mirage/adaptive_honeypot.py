"""
Adaptive Honeypot — Stateful Multi-Level Interaction Engine

Wraps the existing HoneypotMesh with stateful interactions that
escalate based on attacker sophistication. Three interaction levels
draw attackers deeper while collecting more intelligence.

Interaction Levels:
    Level 1 (Banner): Service banner response only
    Level 2 (Auth):   Simulated authentication dialog
    Level 3 (Shell):  Fake filesystem / command execution

Sophistication Classifier:
    NAIVE:        Uses default credentials, scans sequentially
    INTERMEDIATE: Custom payloads, irregular timing
    ADVANCED:     Evasion techniques, encrypted C2, slow-and-low

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum, auto
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class InteractionLevel(IntEnum):
    """Honeypot interaction depth."""
    BANNER = 1    # Just return a service banner
    AUTH = 2      # Simulate login prompt / auth dialog
    SHELL = 3     # Fake filesystem and command execution


class SophisticationLevel(IntEnum):
    """Attacker sophistication classification."""
    NAIVE = 1         # Script kiddie, automated tool
    INTERMEDIATE = 2  # Custom payloads, some evasion
    ADVANCED = 3      # APT-style, slow-and-low


# Default credentials that attackers commonly try
COMMON_CREDENTIALS = {
    ("admin", "admin"), ("root", "root"), ("admin", "password"),
    ("root", "toor"), ("admin", "123456"), ("user", "user"),
    ("root", "password"), ("admin", "1234"), ("test", "test"),
    ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("admin", ""),
}

# Fake filesystem entries for Level 3
FAKE_FILESYSTEM = {
    "/": ["bin", "etc", "home", "opt", "tmp", "usr", "var"],
    "/etc": ["passwd", "shadow", "hosts", "ssh", "nginx"],
    "/etc/ssh": ["sshd_config", "authorized_keys"],
    "/home": ["admin", "deploy"],
    "/home/admin": [".ssh", ".bash_history", "notes.txt", "backup.tar.gz"],
    "/tmp": ["sess_a1b2c3", ".npm-cache"],
    "/opt": ["app", "data"],
    "/opt/app": ["config.yml", "server.py", "requirements.txt"],
    "/var/log": ["auth.log", "syslog", "nginx"],
}

# Fake command outputs for Level 3
FAKE_COMMANDS = {
    "whoami": "admin",
    "id": "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)",
    "uname -a": "Linux prod-web-01 5.15.0-84-generic #93-Ubuntu SMP x86_64 GNU/Linux",
    "hostname": "prod-web-01",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\nnginx:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.200.0.50  netmask 255.255.255.0  broadcast 10.200.0.255",
    "cat /opt/app/config.yml": "database:\n  host: db-internal.local\n  port: 5432\n  name: production\n  # credentials in vault",
    "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 169332 11600 ?        Ss   Jan01   0:12 /sbin/init\nadmin      712  0.3  1.2 785432 102400 ?       Sl   08:00   1:32 python3 /opt/app/server.py",
    "netstat -tlnp": "tcp  0  0 0.0.0.0:8080   0.0.0.0:*  LISTEN  712/python3\ntcp  0  0 0.0.0.0:22     0.0.0.0:*  LISTEN  432/sshd",
}


@dataclass
class HoneypotSession:
    """Tracks a single attacker's interaction with a honeypot."""
    source_ip: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    level: InteractionLevel = InteractionLevel.BANNER
    sophistication: SophisticationLevel = SophisticationLevel.NAIVE
    commands_received: List[str] = field(default_factory=list)
    credentials_tried: List[tuple] = field(default_factory=list)
    payloads_captured: List[str] = field(default_factory=list)
    ports_interacted: Set[int] = field(default_factory=set)
    bytes_received: int = 0
    auth_attempts: int = 0
    escalated: bool = False

    @property
    def duration_seconds(self) -> float:
        return (self.last_activity - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "started_at": self.started_at.isoformat(),
            "duration_s": self.duration_seconds,
            "level": self.level.name,
            "sophistication": self.sophistication.name,
            "commands": self.commands_received[-20:],
            "credentials_tried": len(self.credentials_tried),
            "payloads": len(self.payloads_captured),
            "ports": list(self.ports_interacted),
            "bytes_received": self.bytes_received,
        }


class AdaptiveHoneypot:
    """
    Stateful honeypot interaction engine.

    Wraps HoneypotMesh responses with multi-level interaction that
    adapts to attacker sophistication.
    """

    def __init__(
        self,
        orchestrator=None,
        max_sessions: int = 100,
        auto_escalate_after_s: float = 60.0,
    ):
        self._orchestrator = orchestrator
        self._sessions: Dict[str, HoneypotSession] = {}
        self._max_sessions = max_sessions
        self._auto_escalate_after = auto_escalate_after_s
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)

        self._stats = {
            "sessions_created": 0,
            "level1_responses": 0,
            "level2_responses": 0,
            "level3_responses": 0,
            "credentials_captured": 0,
            "commands_captured": 0,
            "payloads_captured": 0,
        }

        logger.info("AdaptiveHoneypot initialized (max_sessions=%d)", max_sessions)

    # ------------------------------------------------------------------
    # Session Management
    # ------------------------------------------------------------------

    def get_or_create_session(self, source_ip: str) -> HoneypotSession:
        """Get existing session or create new one."""
        if source_ip not in self._sessions:
            if len(self._sessions) >= self._max_sessions:
                self._evict_oldest()
            self._sessions[source_ip] = HoneypotSession(source_ip=source_ip)
            self._stats["sessions_created"] += 1
            logger.info("Mirage session created for %s", source_ip)
        return self._sessions[source_ip]

    def close_session(self, source_ip: str) -> Optional[HoneypotSession]:
        """Close and return a session."""
        session = self._sessions.pop(source_ip, None)
        if session:
            logger.info(
                "Mirage session closed for %s (duration=%.0fs, level=%s, cmds=%d)",
                source_ip, session.duration_seconds,
                session.level.name, len(session.commands_received),
            )
            self._emit("session_closed", session)
        return session

    # ------------------------------------------------------------------
    # Interaction Handlers
    # ------------------------------------------------------------------

    def handle_banner_request(
        self,
        source_ip: str,
        port: int,
        service_type: str = "",
    ) -> str:
        """Level 1: Return service banner."""
        session = self.get_or_create_session(source_ip)
        session.ports_interacted.add(port)
        session.last_activity = datetime.utcnow()
        self._stats["level1_responses"] += 1

        # Classify sophistication from timing patterns
        self._update_sophistication(session)

        if session.level == InteractionLevel.BANNER:
            self._check_level_escalation(session)

        return self._generate_banner(port, service_type)

    def handle_auth_attempt(
        self,
        source_ip: str,
        username: str,
        password: str,
        service: str = "ssh",
    ) -> Dict[str, Any]:
        """Level 2: Process authentication attempt."""
        session = self.get_or_create_session(source_ip)
        session.last_activity = datetime.utcnow()
        session.auth_attempts += 1
        session.credentials_tried.append((username, password))
        self._stats["credentials_captured"] += 1

        # Escalate to Level 2 if not already
        if session.level < InteractionLevel.AUTH:
            session.level = InteractionLevel.AUTH
            logger.info("Mirage %s → Level 2 (AUTH) after credential attempt", source_ip)

        self._stats["level2_responses"] += 1
        self._update_sophistication(session)

        # Always fail first 2 attempts, then "succeed" to draw them in
        if session.auth_attempts <= 2:
            return {
                "success": False,
                "message": "Authentication failed",
                "allow_retry": True,
            }

        # "Success" — escalate to Level 3
        if session.level < InteractionLevel.SHELL:
            session.level = InteractionLevel.SHELL
            logger.info("Mirage %s → Level 3 (SHELL) after auth 'success'", source_ip)
            self._emit("level_escalated", session)

        return {
            "success": True,
            "message": f"Welcome {username}@prod-web-01",
            "prompt": f"{username}@prod-web-01:~$ ",
        }

    def handle_command(
        self,
        source_ip: str,
        command: str,
    ) -> str:
        """Level 3: Process command execution in fake shell."""
        session = self.get_or_create_session(source_ip)
        session.last_activity = datetime.utcnow()
        session.commands_received.append(command)
        self._stats["commands_captured"] += 1
        self._stats["level3_responses"] += 1

        if session.level < InteractionLevel.SHELL:
            session.level = InteractionLevel.SHELL

        self._update_sophistication(session)

        # Check for payload / tool downloads
        if any(kw in command for kw in ("wget ", "curl ", "nc ", "base64", "/dev/tcp")):
            session.payloads_captured.append(command)
            self._stats["payloads_captured"] += 1
            self._emit("payload_captured", session)

        # Notify orchestrator for profiling transition
        if not session.escalated and len(session.commands_received) >= 5:
            session.escalated = True
            if self._orchestrator:
                self._orchestrator.transition_to_profiling(source_ip)

        return self._execute_fake_command(command)

    def handle_payload(
        self,
        source_ip: str,
        payload: bytes,
        port: int,
    ) -> None:
        """Capture raw payload data from attacker."""
        session = self.get_or_create_session(source_ip)
        session.bytes_received += len(payload)
        session.last_activity = datetime.utcnow()

        payload_hash = hashlib.sha256(payload[:4096]).hexdigest()[:16]
        session.payloads_captured.append(payload_hash)
        self._stats["payloads_captured"] += 1

        logger.info(
            "Mirage payload captured from %s port %d (%d bytes, hash=%s)",
            source_ip, port, len(payload), payload_hash,
        )
        self._emit("payload_captured", session)

    # ------------------------------------------------------------------
    # Sophistication Classification
    # ------------------------------------------------------------------

    def _update_sophistication(self, session: HoneypotSession) -> None:
        """Update attacker sophistication level based on behavior."""
        old = session.sophistication

        # Advanced indicators
        if self._has_advanced_indicators(session):
            session.sophistication = SophisticationLevel.ADVANCED
        elif self._has_intermediate_indicators(session):
            session.sophistication = SophisticationLevel.INTERMEDIATE

        if session.sophistication != old:
            logger.info(
                "Mirage %s sophistication: %s → %s",
                session.source_ip, old.name, session.sophistication.name,
            )
            self._emit("sophistication_changed", session)

    def _has_advanced_indicators(self, session: HoneypotSession) -> bool:
        """Check for APT-style behavior."""
        # Slow-and-low: long duration with few commands
        if session.duration_seconds > 300 and len(session.commands_received) < 5:
            return True
        # Uses non-default credentials
        if session.credentials_tried:
            non_common = [c for c in session.credentials_tried if c not in COMMON_CREDENTIALS]
            if len(non_common) > len(session.credentials_tried) * 0.5:
                return True
        # Enumeration commands typical of manual post-exploitation
        enum_cmds = {"cat /etc/shadow", "find / -perm", "grep -r password",
                     "cat /proc", "env", "set", "history"}
        used_enum = sum(1 for c in session.commands_received if any(e in c for e in enum_cmds))
        if used_enum >= 3:
            return True
        return False

    def _has_intermediate_indicators(self, session: HoneypotSession) -> bool:
        """Check for custom tool / scripted behavior."""
        # Multiple ports in rapid succession
        if len(session.ports_interacted) >= 3:
            return True
        # Custom payloads
        if session.payloads_captured:
            return True
        # Non-default credentials on first try
        if session.credentials_tried and session.credentials_tried[0] not in COMMON_CREDENTIALS:
            return True
        return False

    # ------------------------------------------------------------------
    # Response Generation
    # ------------------------------------------------------------------

    def _generate_banner(self, port: int, service_type: str = "") -> str:
        """Generate a realistic service banner."""
        banners = {
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            21: "220 Microsoft FTP Service",
            23: "Ubuntu 22.04 LTS\nlogin: ",
            25: "220 mail.internal.local ESMTP Postfix",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)",
            443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
            3306: "5.7.32-0ubuntu0.18.04.1",
            5432: "PostgreSQL 14.2 on x86_64-pc-linux-gnu",
            3389: "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00",
            445: "SMBv3",
            6379: "+OK Redis 6.0.16 ready",
            9200: '{"name":"prod-es-01","cluster_name":"production","version":{"number":"7.17.6"}}',
        }
        return banners.get(port, f"Service ready on port {port}")

    def _execute_fake_command(self, command: str) -> str:
        """Execute a command against the fake filesystem."""
        cmd = command.strip()

        # Direct command matches
        if cmd in FAKE_COMMANDS:
            return FAKE_COMMANDS[cmd]

        # ls command
        if cmd.startswith("ls"):
            path = cmd.split()[-1] if len(cmd.split()) > 1 else "/home/admin"
            path = path.rstrip("/") or "/"
            entries = FAKE_FILESYSTEM.get(path)
            if entries:
                return "  ".join(entries)
            return f"ls: cannot access '{path}': No such file or directory"

        # cat command
        if cmd.startswith("cat "):
            target = cmd[4:].strip()
            if target in FAKE_COMMANDS:
                return FAKE_COMMANDS[target]
            return f"cat: {target}: No such file or directory"

        # cd command
        if cmd.startswith("cd "):
            path = cmd[3:].strip()
            if path in FAKE_FILESYSTEM or path == "~":
                return ""
            return f"-bash: cd: {path}: No such file or directory"

        # pwd
        if cmd == "pwd":
            return "/home/admin"

        # echo
        if cmd.startswith("echo "):
            return cmd[5:]

        # Catch-all
        if cmd:
            return f"-bash: {cmd.split()[0]}: command not found"
        return ""

    # ------------------------------------------------------------------
    # Level Escalation
    # ------------------------------------------------------------------

    def _check_level_escalation(self, session: HoneypotSession) -> None:
        """Auto-escalate interaction level based on engagement."""
        if session.level >= InteractionLevel.AUTH:
            return

        # Multiple ports touched → ready for auth
        if len(session.ports_interacted) >= 2:
            session.level = InteractionLevel.AUTH
            logger.info("Mirage %s auto-escalated to Level 2 (AUTH)", session.source_ip)
            self._emit("level_escalated", session)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def on(self, event: str, callback: Callable) -> None:
        """Register callback: session_closed, level_escalated,
        sophistication_changed, payload_captured."""
        self._callbacks[event].append(callback)

    def _emit(self, event: str, session: HoneypotSession) -> None:
        for cb in self._callbacks.get(event, []):
            try:
                cb(event, session)
            except Exception as e:
                logger.error("AdaptiveHoneypot callback error [%s]: %s", event, e)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_session(self, source_ip: str) -> Optional[HoneypotSession]:
        return self._sessions.get(source_ip)

    def get_active_sessions(self) -> List[HoneypotSession]:
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        return [s for s in self._sessions.values() if s.last_activity > cutoff]

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "active_sessions": len(self._sessions),
        }

    def _evict_oldest(self) -> None:
        """Remove the oldest session to make room."""
        if not self._sessions:
            return
        oldest_ip = min(self._sessions, key=lambda ip: self._sessions[ip].last_activity)
        self._sessions.pop(oldest_ip, None)
