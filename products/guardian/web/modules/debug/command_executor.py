"""
Command Executor - Safe command execution with strict whitelist

Security model:
- Only whitelisted commands can be executed
- Arguments are validated and sanitized
- Output is streamed for long-running commands
- Rate limiting prevents abuse
"""
import os
import re
import shlex
import subprocess
import threading
import time
from typing import Dict, Generator, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class CommandCategory(Enum):
    """Categories of allowed commands."""
    NETWORK = "network"
    SYSTEM = "system"
    CONTAINERS = "containers"
    LOGS = "logs"
    DNS = "dns"


@dataclass
class CommandSpec:
    """Specification for an allowed command."""
    name: str
    category: CommandCategory
    description: str
    timeout: int = 30
    allowed_args: Optional[List[str]] = None  # None = any args allowed
    allowed_subcommands: Optional[List[str]] = None  # For commands like 'ip addr'
    max_args: int = 5
    requires_arg: bool = False
    dangerous: bool = False  # If True, requires confirmation


# Whitelist of allowed commands
COMMAND_WHITELIST: Dict[str, CommandSpec] = {
    # Network diagnostics
    'ping': CommandSpec(
        name='ping',
        category=CommandCategory.NETWORK,
        description='Test network connectivity to a host',
        timeout=15,
        max_args=2,
        requires_arg=True
    ),
    'traceroute': CommandSpec(
        name='traceroute',
        category=CommandCategory.NETWORK,
        description='Trace route to a host',
        timeout=60,
        max_args=1,
        requires_arg=True
    ),
    'mtr': CommandSpec(
        name='mtr',
        category=CommandCategory.NETWORK,
        description='Network diagnostic tool (traceroute + ping)',
        timeout=30,
        allowed_args=['-r', '-c', '--report', '--report-cycles'],
        max_args=3,
        requires_arg=True
    ),
    'curl': CommandSpec(
        name='curl',
        category=CommandCategory.NETWORK,
        description='Transfer data from URL (headers only)',
        timeout=30,
        allowed_args=['-I', '-s', '-w', '--head', '--silent'],
        max_args=4,
        requires_arg=True
    ),

    # DNS
    'dig': CommandSpec(
        name='dig',
        category=CommandCategory.DNS,
        description='DNS lookup utility',
        timeout=15,
        max_args=4
    ),
    'nslookup': CommandSpec(
        name='nslookup',
        category=CommandCategory.DNS,
        description='Query DNS servers',
        timeout=15,
        max_args=2
    ),
    'host': CommandSpec(
        name='host',
        category=CommandCategory.DNS,
        description='DNS lookup utility',
        timeout=15,
        max_args=2
    ),

    # Network info
    'ip': CommandSpec(
        name='ip',
        category=CommandCategory.NETWORK,
        description='Show IP addresses and routes',
        timeout=10,
        allowed_subcommands=['addr', 'address', 'route', 'link', 'neigh', 'neighbor'],
        max_args=3
    ),
    'ifconfig': CommandSpec(
        name='ifconfig',
        category=CommandCategory.NETWORK,
        description='Show network interface configuration',
        timeout=10,
        max_args=1
    ),
    'iwconfig': CommandSpec(
        name='iwconfig',
        category=CommandCategory.NETWORK,
        description='Show wireless interface configuration',
        timeout=10,
        max_args=1
    ),
    'ss': CommandSpec(
        name='ss',
        category=CommandCategory.NETWORK,
        description='Show socket statistics',
        timeout=10,
        allowed_args=['-t', '-u', '-l', '-n', '-p', '-a', '-tuln', '-tulnp'],
        max_args=4
    ),
    'netstat': CommandSpec(
        name='netstat',
        category=CommandCategory.NETWORK,
        description='Network statistics',
        timeout=10,
        allowed_args=['-t', '-u', '-l', '-n', '-p', '-a', '-tuln', '-tulnp', '-r'],
        max_args=4
    ),
    'arp': CommandSpec(
        name='arp',
        category=CommandCategory.NETWORK,
        description='Show ARP cache',
        timeout=10,
        allowed_args=['-a', '-n'],
        max_args=2
    ),

    # System info
    'uptime': CommandSpec(
        name='uptime',
        category=CommandCategory.SYSTEM,
        description='Show system uptime',
        timeout=5,
        max_args=0
    ),
    'free': CommandSpec(
        name='free',
        category=CommandCategory.SYSTEM,
        description='Show memory usage',
        timeout=5,
        allowed_args=['-h', '-m', '-g', '--human'],
        max_args=1
    ),
    'df': CommandSpec(
        name='df',
        category=CommandCategory.SYSTEM,
        description='Show disk space usage',
        timeout=10,
        allowed_args=['-h', '--human-readable'],
        max_args=1
    ),
    'ps': CommandSpec(
        name='ps',
        category=CommandCategory.SYSTEM,
        description='Show running processes',
        timeout=10,
        allowed_args=['aux', 'ef', '-ef', '-aux'],
        max_args=1
    ),
    'top': CommandSpec(
        name='top',
        category=CommandCategory.SYSTEM,
        description='Show top processes (snapshot)',
        timeout=5,
        allowed_args=['-b', '-n', '1', '-n1'],
        max_args=3
    ),
    'uname': CommandSpec(
        name='uname',
        category=CommandCategory.SYSTEM,
        description='Show system information',
        timeout=5,
        allowed_args=['-a', '-r', '-m', '-n', '-s'],
        max_args=1
    ),
    'hostname': CommandSpec(
        name='hostname',
        category=CommandCategory.SYSTEM,
        description='Show hostname',
        timeout=5,
        max_args=0
    ),
    'date': CommandSpec(
        name='date',
        category=CommandCategory.SYSTEM,
        description='Show current date and time',
        timeout=5,
        max_args=0
    ),
    'whoami': CommandSpec(
        name='whoami',
        category=CommandCategory.SYSTEM,
        description='Show current user',
        timeout=5,
        max_args=0
    ),
    'id': CommandSpec(
        name='id',
        category=CommandCategory.SYSTEM,
        description='Show user identity',
        timeout=5,
        max_args=0
    ),

    # Container commands
    'podman': CommandSpec(
        name='podman',
        category=CommandCategory.CONTAINERS,
        description='Container management (ps, logs, inspect)',
        timeout=30,
        allowed_subcommands=['ps', 'logs', 'inspect', 'images', 'stats'],
        max_args=4
    ),
    'docker': CommandSpec(
        name='docker',
        category=CommandCategory.CONTAINERS,
        description='Container management (ps, logs, inspect)',
        timeout=30,
        allowed_subcommands=['ps', 'logs', 'inspect', 'images', 'stats'],
        max_args=4
    ),

    # Logs
    'journalctl': CommandSpec(
        name='journalctl',
        category=CommandCategory.LOGS,
        description='Query systemd journal',
        timeout=30,
        allowed_args=['-n', '-f', '-u', '--no-pager', '-e', '-x', '-b', '--since'],
        max_args=6
    ),
    'dmesg': CommandSpec(
        name='dmesg',
        category=CommandCategory.LOGS,
        description='Show kernel ring buffer',
        timeout=10,
        allowed_args=['-T', '-H', '--human', '-l', 'err', 'warn'],
        max_args=3
    ),

    # Service status (read-only)
    'systemctl': CommandSpec(
        name='systemctl',
        category=CommandCategory.SYSTEM,
        description='Show service status',
        timeout=15,
        allowed_subcommands=['status', 'is-active', 'is-enabled', 'list-units'],
        max_args=3
    ),

    # Guardian-specific
    'cat': CommandSpec(
        name='cat',
        category=CommandCategory.LOGS,
        description='View log files (restricted paths)',
        timeout=10,
        max_args=1,
        requires_arg=True
    ),
    'tail': CommandSpec(
        name='tail',
        category=CommandCategory.LOGS,
        description='View end of log files',
        timeout=10,
        allowed_args=['-n', '-f', '-100', '-50', '-20'],
        max_args=3,
        requires_arg=True
    ),
    'head': CommandSpec(
        name='head',
        category=CommandCategory.LOGS,
        description='View start of log files',
        timeout=10,
        allowed_args=['-n', '-100', '-50', '-20'],
        max_args=3,
        requires_arg=True
    ),
    'wc': CommandSpec(
        name='wc',
        category=CommandCategory.LOGS,
        description='Count lines/words in files',
        timeout=10,
        allowed_args=['-l', '-w', '-c'],
        max_args=2
    ),

    # Help
    'help': CommandSpec(
        name='help',
        category=CommandCategory.SYSTEM,
        description='Show available commands',
        timeout=5,
        max_args=1
    ),
    'clear': CommandSpec(
        name='clear',
        category=CommandCategory.SYSTEM,
        description='Clear terminal screen',
        timeout=1,
        max_args=0
    ),
}

# Allowed paths for file operations (cat, tail, head)
ALLOWED_FILE_PATHS = [
    '/var/log/',
    '/var/log/hookprobe/',
    '/var/log/suricata/',
    '/var/log/nginx/',
    '/opt/hookprobe/logs/',
    '/tmp/guardian-',
    '/proc/loadavg',
    '/proc/meminfo',
    '/proc/cpuinfo',
    '/proc/uptime',
    '/proc/version',
    '/etc/resolv.conf',
    '/etc/hosts',
]

# Dangerous patterns to block
DANGEROUS_PATTERNS = [
    r'[;&|`$]',   # Command chaining/substitution
    r'\.\.',      # Path traversal
    r'>\s*/',     # Redirect to root
    r'<\s*/',     # Read from root
    r'\bsudo\b',  # Sudo attempts
    r'\brm\b',    # Remove commands
    r'\bdd\b',    # Disk destroyer
    r'\bmkfs\b',  # Filesystem creation
    r'\bformat\b',
    r'\breboot\b',
    r'\bshutdown\b',
    r'\bhalt\b',
    r'\bpoweroff\b',
]


class RateLimiter:
    """Simple rate limiter for command execution."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: List[float] = []
        self.lock = threading.Lock()

    def is_allowed(self) -> bool:
        """Check if a request is allowed."""
        with self.lock:
            now = time.time()
            # Remove old requests
            self.requests = [t for t in self.requests if now - t < self.window_seconds]

            if len(self.requests) >= self.max_requests:
                return False

            self.requests.append(now)
            return True

    def get_remaining(self) -> int:
        """Get remaining requests in current window."""
        with self.lock:
            now = time.time()
            self.requests = [t for t in self.requests if now - t < self.window_seconds]
            return max(0, self.max_requests - len(self.requests))


# Global rate limiter
rate_limiter = RateLimiter()


def validate_command(command_line: str) -> Tuple[bool, str, Optional[List[str]]]:
    """
    Validate a command against the whitelist.

    Returns:
        Tuple of (is_valid, error_message, parsed_args)
    """
    if not command_line or not command_line.strip():
        return False, "Empty command", None

    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command_line, re.IGNORECASE):
            return False, "Command contains blocked pattern", None

    # Parse command
    try:
        args = shlex.split(command_line)
    except ValueError as e:
        return False, f"Invalid command syntax: {e}", None

    if not args:
        return False, "Empty command", None

    cmd_name = args[0].lower()

    # Handle built-in commands
    if cmd_name == 'help':
        return True, "", args
    if cmd_name == 'clear':
        return True, "", args

    # Check whitelist
    if cmd_name not in COMMAND_WHITELIST:
        msg = f"Command '{cmd_name}' is not allowed. Type 'help' for available commands."
        return False, msg, None

    spec = COMMAND_WHITELIST[cmd_name]
    cmd_args = args[1:]

    # Check argument count
    if len(cmd_args) > spec.max_args:
        return False, f"Too many arguments (max {spec.max_args})", None

    # Check required argument
    if spec.requires_arg and not cmd_args:
        return False, f"Command '{cmd_name}' requires an argument", None

    # Check subcommands (for commands like 'ip addr', 'podman ps')
    if spec.allowed_subcommands and cmd_args:
        subcommand = cmd_args[0]
        if subcommand not in spec.allowed_subcommands:
            allowed = ', '.join(spec.allowed_subcommands)
            return False, f"Subcommand '{subcommand}' not allowed. Allowed: {allowed}", None

    # Enforce allowed_args whitelist (flags/options)
    if spec.allowed_args is not None and cmd_args:
        for arg in cmd_args:
            if arg.startswith('-') and arg not in spec.allowed_args:
                allowed = ', '.join(spec.allowed_args)
                return False, f"Argument '{arg}' not allowed. Allowed: {allowed}", None

    # Check file paths for cat/tail/head
    if cmd_name in ('cat', 'tail', 'head'):
        # Find the file argument (skip flags)
        file_arg = None
        for arg in cmd_args:
            if not arg.startswith('-'):
                file_arg = arg
                break

        if file_arg:
            # Resolve path (realpath resolves symlinks to prevent symlink-based bypass)
            file_path = os.path.realpath(file_arg)
            is_allowed = any(
                file_path == allowed.rstrip('/') or file_path.startswith(allowed if allowed.endswith('/') else allowed + '/')
                for allowed in ALLOWED_FILE_PATHS
                if '/' in allowed
            ) or file_path in ALLOWED_FILE_PATHS
            if not is_allowed:
                return False, f"Access to '{file_arg}' is not allowed", None

    return True, "", args


def generate_help() -> str:
    """Generate help text for available commands."""
    lines = [
        "Guardian Debug CLI - Available Commands",
        "=" * 45,
        ""
    ]

    # Group by category
    categories: Dict[CommandCategory, List[CommandSpec]] = {}
    for spec in COMMAND_WHITELIST.values():
        if spec.category not in categories:
            categories[spec.category] = []
        categories[spec.category].append(spec)

    category_order = [
        CommandCategory.NETWORK,
        CommandCategory.DNS,
        CommandCategory.SYSTEM,
        CommandCategory.CONTAINERS,
        CommandCategory.LOGS,
    ]

    for category in category_order:
        if category in categories:
            lines.append(f"\n[{category.value.upper()}]")
            for spec in sorted(categories[category], key=lambda x: x.name):
                lines.append(f"  {spec.name:<12} - {spec.description}")

    lines.extend([
        "",
        "Special Commands:",
        "  help         - Show this help",
        "  clear        - Clear terminal",
        "",
        "Note: Commands are rate-limited and output may be truncated.",
    ])

    return '\n'.join(lines)


def execute_command(command_line: str) -> Generator[str, None, None]:
    """
    Execute a validated command and yield output lines.

    Yields:
        Output lines as strings
    """
    # Rate limiting
    if not rate_limiter.is_allowed():
        yield "[ERROR] Rate limit exceeded. Please wait before running more commands.\n"
        return

    # Validate
    is_valid, error, args = validate_command(command_line)
    if not is_valid:
        yield f"[ERROR] {error}\n"
        return

    cmd_name = args[0].lower()

    # Handle built-in commands
    if cmd_name == 'help':
        if len(args) > 1:
            # Help for specific command
            target = args[1].lower()
            if target in COMMAND_WHITELIST:
                spec = COMMAND_WHITELIST[target]
                yield f"{spec.name}: {spec.description}\n"
                yield f"  Category: {spec.category.value}\n"
                yield f"  Timeout: {spec.timeout}s\n"
                if spec.allowed_subcommands:
                    yield f"  Subcommands: {', '.join(spec.allowed_subcommands)}\n"
                if spec.allowed_args:
                    yield f"  Allowed args: {', '.join(spec.allowed_args)}\n"
            else:
                yield f"[ERROR] Unknown command: {target}\n"
        else:
            yield generate_help()
            yield "\n"
        return

    if cmd_name == 'clear':
        yield "\x1b[2J\x1b[H"  # ANSI clear screen
        return

    spec = COMMAND_WHITELIST[cmd_name]

    # Special handling for ping (limit count)
    if cmd_name == 'ping':
        # Add -c 4 if not specified
        if '-c' not in args:
            args = [args[0], '-c', '4'] + args[1:]

    # Special handling for top (batch mode)
    if cmd_name == 'top':
        if '-b' not in args:
            args = [args[0], '-b', '-n', '1'] + args[1:]

    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        start_time = time.time()
        output_lines = 0
        max_lines = 500

        for line in iter(process.stdout.readline, ''):
            if not line:
                break

            # Check timeout
            if time.time() - start_time > spec.timeout:
                process.kill()
                yield f"\n[TIMEOUT] Command exceeded {spec.timeout}s limit\n"
                break

            # Line limit
            output_lines += 1
            if output_lines > max_lines:
                process.kill()
                yield f"\n[TRUNCATED] Output exceeded {max_lines} lines\n"
                break

            yield line

        process.wait(timeout=2)

        if process.returncode != 0 and output_lines == 0:
            yield f"[EXIT CODE: {process.returncode}]\n"

    except FileNotFoundError:
        yield f"[ERROR] Command '{cmd_name}' not found on this system\n"
    except subprocess.TimeoutExpired:
        yield "[TIMEOUT] Command did not complete\n"
    except Exception as e:
        yield f"[ERROR] {str(e)}\n"


def get_command_categories() -> Dict[str, List[Dict]]:
    """Get commands grouped by category for UI display."""
    categories: Dict[str, List[Dict]] = {}

    for name, spec in COMMAND_WHITELIST.items():
        cat_name = spec.category.value
        if cat_name not in categories:
            categories[cat_name] = []

        categories[cat_name].append({
            'name': name,
            'description': spec.description,
            'timeout': spec.timeout
        })

    return categories
