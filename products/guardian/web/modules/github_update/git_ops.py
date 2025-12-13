"""
Git Operations - Safe git command wrappers for GitHub updates

All operations are read-only or use --ff-only for safety.
Designed to work without CLI access (via web UI).
"""
import os
import subprocess
import shlex
from typing import Dict, List, Tuple


def run_command(cmd, timeout=30):
    """Execute a command safely without shell=True to prevent command injection."""
    try:
        # Convert string to list for safe execution
        if isinstance(cmd, str):
            cmd_list = shlex.split(cmd)
        else:
            cmd_list = cmd

        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.returncode == 0
    except subprocess.TimeoutExpired:
        return "Command timed out", False
    except Exception as e:
        return str(e), False


# Configuration
REPO_PATH = os.environ.get('GUARDIAN_REPO_PATH', '/opt/hookprobe')
REMOTE_NAME = 'origin'
DEFAULT_BRANCH = os.environ.get('GUARDIAN_BRANCH', 'main')

# Cache for detected repo path
_cached_repo_path = None

# Allowed paths for updates (networking-related only)
ALLOWED_UPDATE_PATHS = [
    'products/guardian/',
    'shared/dnsXai/',
    'shared/mesh/',
    'shared/response/',
    'shared/cortex/',        # Cortex globe visualization (embedded in Guardian)
]

# Services that can be restarted after update
ALLOWED_SERVICES = [
    'dnsmasq',
    'hostapd',
    'dnsxai',
    'guardian-agent',
    'guardian-webui',
    'guardian-qsecbit',
    'guardian-wlan',
    'nginx',
]


def get_repo_path() -> str:
    """Get the repository path, validating it exists. Result is cached."""
    global _cached_repo_path

    # Return cached path if already detected
    if _cached_repo_path is not None:
        return _cached_repo_path

    # Check environment variable path first
    if os.path.isdir(os.path.join(REPO_PATH, '.git')):
        _cached_repo_path = REPO_PATH
        return _cached_repo_path

    # Try common installation paths
    common_paths = [
        '/opt/hookprobe',
        '/home/user/hookprobe',
        '/home/pi/hookprobe',
        '/home/guardian/hookprobe',
        os.path.expanduser('~/hookprobe'),
    ]

    for path in common_paths:
        if os.path.isdir(os.path.join(path, '.git')):
            _cached_repo_path = path
            return _cached_repo_path

    # Try to find repo by traversing up from current file location
    current_dir = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):  # Max 10 levels up
        if os.path.isdir(os.path.join(current_dir, '.git')):
            _cached_repo_path = current_dir
            return _cached_repo_path
        parent = os.path.dirname(current_dir)
        if parent == current_dir:  # Reached root
            break
        current_dir = parent

    # Fallback to current working directory if it's a git repo
    cwd = os.getcwd()
    if os.path.isdir(os.path.join(cwd, '.git')):
        _cached_repo_path = cwd
        return _cached_repo_path

    # Last resort: use git to find repo root from this file's location
    this_file_dir = os.path.dirname(os.path.abspath(__file__))
    output, success = run_command(
        ['git', '-C', this_file_dir, 'rev-parse', '--show-toplevel']
    )
    if success and output and os.path.isdir(output):
        _cached_repo_path = output
        return _cached_repo_path

    _cached_repo_path = REPO_PATH
    return _cached_repo_path


def get_current_status() -> Dict:
    """
    Get current git repository status.

    Returns:
        Dict with current_commit, current_branch, repo_path, is_valid
    """
    repo_path = get_repo_path()

    # Check if path exists and has .git
    git_dir = os.path.join(repo_path, '.git')
    if not os.path.isdir(git_dir):
        return {
            'current_commit': 'not found',
            'full_commit': 'not found',
            'current_branch': 'not found',
            'commit_date': 'unknown',
            'repo_path': repo_path,
            'is_valid': False,
            'error': f'Git directory not found at {repo_path}'
        }

    # Get current commit hash
    commit_output, commit_success = run_command(
        ['git', '-C', repo_path, 'rev-parse', '--short', 'HEAD']
    )

    # Get current branch
    branch_output, branch_success = run_command(
        ['git', '-C', repo_path, 'rev-parse', '--abbrev-ref', 'HEAD']
    )

    # Get full commit hash for comparison
    full_commit, _ = run_command(
        ['git', '-C', repo_path, 'rev-parse', 'HEAD']
    )

    # Get commit date
    date_output, _ = run_command(
        ['git', '-C', repo_path, 'log', '-1', '--format=%ci']
    )

    result = {
        'current_commit': commit_output if commit_success else 'error',
        'full_commit': full_commit.strip() if full_commit else 'error',
        'current_branch': branch_output if branch_success else 'error',
        'commit_date': date_output.strip() if date_output else 'unknown',
        'repo_path': repo_path,
        'is_valid': commit_success and branch_success
    }

    # Add error info if git commands failed
    if not commit_success:
        result['error'] = f'Git command failed: {commit_output}'

    return result


def fetch_updates() -> Tuple[bool, str]:
    """
    Fetch updates from remote without applying them.

    Returns:
        Tuple of (success, message)
    """
    repo_path = get_repo_path()

    output, success = run_command(
        ['git', '-C', repo_path, 'fetch', REMOTE_NAME],
        timeout=60
    )

    if success:
        return True, 'Successfully fetched updates from remote'
    return False, f'Failed to fetch: {output}'


def check_for_updates() -> Dict:
    """
    Check if updates are available from remote.

    Returns:
        Dict with updates_available, commits_behind, commits list
    """
    repo_path = get_repo_path()
    branch = DEFAULT_BRANCH

    # First fetch to ensure we have latest remote info
    fetch_success, fetch_msg = fetch_updates()
    if not fetch_success:
        return {
            'updates_available': False,
            'error': fetch_msg,
            'commits_behind': 0,
            'commits': []
        }

    # Get current HEAD
    local_head, _ = run_command(
        ['git', '-C', repo_path, 'rev-parse', 'HEAD']
    )

    # Get remote HEAD
    remote_head, _ = run_command(
        ['git', '-C', repo_path, 'rev-parse', f'{REMOTE_NAME}/{branch}']
    )

    if local_head.strip() == remote_head.strip():
        return {
            'updates_available': False,
            'commits_behind': 0,
            'commits': [],
            'message': 'Already up to date'
        }

    # Count commits behind
    count_output, _ = run_command(
        ['git', '-C', repo_path, 'rev-list', '--count',
         f'HEAD..{REMOTE_NAME}/{branch}']
    )
    commits_behind = int(count_output.strip()) if count_output.isdigit() else 0

    # Get commit list (limit to 20 for UI)
    log_output, _ = run_command(
        ['git', '-C', repo_path, 'log', '--oneline',
         f'HEAD..{REMOTE_NAME}/{branch}', '-n', '20']
    )

    commits = []
    if log_output:
        for line in log_output.strip().split('\n'):
            if line:
                parts = line.split(' ', 1)
                if len(parts) >= 2:
                    commits.append({
                        'hash': parts[0],
                        'message': parts[1]
                    })

    return {
        'updates_available': commits_behind > 0,
        'commits_behind': commits_behind,
        'commits': commits,
        'latest_commit': remote_head.strip()[:7] if remote_head else 'unknown'
    }


def preview_changes() -> Dict:
    """
    Preview what files would be changed by an update.

    Returns:
        Dict with files list, filtered to allowed paths
    """
    repo_path = get_repo_path()
    branch = DEFAULT_BRANCH

    # Get diff stat
    diff_output, success = run_command(
        ['git', '-C', repo_path, 'diff', '--stat', '--name-only',
         f'HEAD..{REMOTE_NAME}/{branch}']
    )

    if not success:
        return {'files': [], 'error': 'Failed to get diff'}

    all_files = diff_output.strip().split('\n') if diff_output else []

    # Filter to allowed paths and categorize
    allowed_files = []
    blocked_files = []

    for file_path in all_files:
        if not file_path:
            continue
        is_allowed = any(file_path.startswith(path) for path in ALLOWED_UPDATE_PATHS)
        if is_allowed:
            allowed_files.append(file_path)
        else:
            blocked_files.append(file_path)

    # Determine which services need restart based on changed files
    services_to_restart = determine_services_to_restart(allowed_files)

    return {
        'files': allowed_files,
        'blocked_files': blocked_files,
        'total_changes': len(all_files),
        'allowed_changes': len(allowed_files),
        'services_to_restart': services_to_restart
    }


def determine_services_to_restart(changed_files: List[str]) -> List[str]:
    """
    Determine which services need restart based on changed files.

    Args:
        changed_files: List of file paths that changed

    Returns:
        List of service names to restart
    """
    services = set()

    for file_path in changed_files:
        # Guardian web UI changes
        if file_path.startswith('products/guardian/web/'):
            services.add('guardian-webui')

        # Guardian lib changes
        if file_path.startswith('products/guardian/lib/'):
            services.add('guardian-agent')

        # Guardian config changes
        if file_path.startswith('products/guardian/config/'):
            if 'dnsmasq' in file_path:
                services.add('dnsmasq')
            if 'hostapd' in file_path:
                services.add('hostapd')
            if 'wpa_supplicant' in file_path:
                services.add('guardian-wlan')

        # dnsXai changes
        if file_path.startswith('shared/dnsXai/'):
            services.add('dnsxai')
            services.add('dnsmasq')

        # Mesh changes
        if file_path.startswith('shared/mesh/'):
            services.add('guardian-agent')

        # Response changes
        if file_path.startswith('shared/response/'):
            services.add('guardian-agent')

        # Cortex visualization changes (embedded in Guardian web UI)
        if file_path.startswith('shared/cortex/'):
            services.add('guardian-webui')

    # Filter to only allowed services
    return [s for s in services if s in ALLOWED_SERVICES]


def is_frontend_only_update(changed_files: List[str]) -> bool:
    """
    Check if the update only affects frontend (web UI) files.
    Frontend-only updates don't require system reboot.

    Args:
        changed_files: List of file paths that changed

    Returns:
        True if only frontend files changed
    """
    frontend_paths = [
        'products/guardian/web/',
        'shared/cortex/frontend/',
    ]

    backend_paths = [
        'products/guardian/lib/',
        'products/guardian/config/',
        'shared/dnsXai/',
        'shared/mesh/',
        'shared/response/',
        'shared/cortex/backend/',
    ]

    has_frontend = False
    has_backend = False

    for file_path in changed_files:
        if any(file_path.startswith(p) for p in frontend_paths):
            has_frontend = True
        if any(file_path.startswith(p) for p in backend_paths):
            has_backend = True

    return has_frontend and not has_backend


def categorize_changes(changed_files: List[str]) -> Dict:
    """
    Categorize changed files by component for better UI display.

    Args:
        changed_files: List of file paths that changed

    Returns:
        Dict with categorized files and metadata
    """
    categories = {
        'web_ui': [],      # Guardian web UI templates, JS, CSS
        'cortex': [],      # Cortex visualization
        'backend': [],     # Guardian agent/lib
        'dnsxai': [],      # DNS protection
        'network': [],     # Mesh, config
        'response': [],    # Threat response scripts
        'other': []
    }

    for file_path in changed_files:
        if file_path.startswith('products/guardian/web/'):
            categories['web_ui'].append(file_path)
        elif file_path.startswith('shared/cortex/'):
            categories['cortex'].append(file_path)
        elif file_path.startswith('products/guardian/lib/'):
            categories['backend'].append(file_path)
        elif file_path.startswith('shared/dnsXai/'):
            categories['dnsxai'].append(file_path)
        elif file_path.startswith('shared/mesh/') or file_path.startswith('products/guardian/config/'):
            categories['network'].append(file_path)
        elif file_path.startswith('shared/response/'):
            categories['response'].append(file_path)
        else:
            categories['other'].append(file_path)

    # Remove empty categories
    categories = {k: v for k, v in categories.items() if v}

    return {
        'categories': categories,
        'is_frontend_only': is_frontend_only_update(changed_files),
        'requires_reboot': False,  # Updates via this mechanism never require reboot
        'total_files': len(changed_files)
    }


def pull_updates(dry_run: bool = False) -> Dict:
    """
    Pull updates from remote using fast-forward only (safe).

    Args:
        dry_run: If True, only simulate the pull

    Returns:
        Dict with success status and details
    """
    repo_path = get_repo_path()
    branch = DEFAULT_BRANCH

    if dry_run:
        # Just return what would happen
        preview = preview_changes()
        return {
            'success': True,
            'dry_run': True,
            'would_update': preview['allowed_changes'],
            'files': preview['files'],
            'services_to_restart': preview['services_to_restart']
        }

    # Check for local changes that would prevent pull
    status_output, _ = run_command(
        ['git', '-C', repo_path, 'status', '--porcelain']
    )

    if status_output and status_output.strip():
        return {
            'success': False,
            'error': 'Local changes detected. Please commit or stash changes first.',
            'local_changes': status_output.strip().split('\n')
        }

    # Get preview before pull
    preview = preview_changes()

    # Perform fast-forward only pull (safe - fails on conflicts)
    pull_output, success = run_command(
        ['git', '-C', repo_path, 'pull', '--ff-only', REMOTE_NAME, branch],
        timeout=120
    )

    if success:
        return {
            'success': True,
            'message': 'Successfully pulled updates',
            'output': pull_output,
            'updated_files': preview['files'],
            'services_to_restart': preview['services_to_restart']
        }

    return {
        'success': False,
        'error': f'Pull failed: {pull_output}',
        'hint': 'Fast-forward only pull failed. This usually means there are '
                'conflicting changes. Manual intervention may be required.'
    }


def restart_services(services: List[str]) -> Dict:
    """
    Restart specified services after update.

    Args:
        services: List of service names to restart

    Returns:
        Dict with results for each service
    """
    results = {}

    for service in services:
        if service not in ALLOWED_SERVICES:
            results[service] = {
                'success': False,
                'error': 'Service not in allowed list'
            }
            continue

        output, success = run_command(
            ['sudo', 'systemctl', 'restart', service],
            timeout=30
        )

        results[service] = {
            'success': success,
            'output': output if not success else 'Restarted successfully'
        }

    return {
        'success': all(r['success'] for r in results.values()),
        'results': results
    }


def get_update_log() -> List[Dict]:
    """
    Get recent git log for the repository.

    Returns:
        List of recent commits
    """
    repo_path = get_repo_path()

    log_output, success = run_command(
        ['git', '-C', repo_path, 'log', '--oneline', '-n', '10',
         '--format=%h|%s|%ci|%an']
    )

    if not success or not log_output:
        return []

    commits = []
    for line in log_output.strip().split('\n'):
        if line:
            parts = line.split('|', 3)
            if len(parts) >= 4:
                commits.append({
                    'hash': parts[0],
                    'message': parts[1],
                    'date': parts[2],
                    'author': parts[3]
                })

    return commits
