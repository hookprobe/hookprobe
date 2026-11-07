"""
Fortress Tunnel Views - Cloudflare Tunnel setup wizard and management.

Provides:
- Setup wizard for configuring remote access
- Status monitoring
- Start/stop controls
- Connectivity testing
"""

from flask import render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user

from . import tunnel_bp
from ..auth.decorators import admin_required

# Import tunnel manager (with fallback for development)
TUNNEL_AVAILABLE = False
tunnel_manager = None

try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'lib'))
    from cloudflare_tunnel import (
        CloudflareTunnelManager,
        TunnelState,
        get_tunnel_manager,
        is_tunnel_available,
        get_tunnel_status,
    )
    tunnel_manager = get_tunnel_manager()
    TUNNEL_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Tunnel manager not available: {e}")


def get_demo_status():
    """Return demo status when manager unavailable."""
    return {
        'state': 'unconfigured',
        'hostname': None,
        'uptime_seconds': 0,
        'bytes_in': 0,
        'bytes_out': 0,
        'connections': 0,
        'last_error': None,
        'cloudflared_version': None,
    }


@tunnel_bp.route('/')
@login_required
def index():
    """Tunnel overview and status page."""
    status = get_demo_status()
    config = None

    if TUNNEL_AVAILABLE and tunnel_manager:
        status = tunnel_manager.get_status().to_dict()
        config = tunnel_manager.get_config()

    # Determine which view to show
    show_wizard = status['state'] in ('not_installed', 'unconfigured')

    return render_template(
        'tunnel/index.html',
        status=status,
        config=config,
        show_wizard=show_wizard,
        tunnel_available=TUNNEL_AVAILABLE
    )


@tunnel_bp.route('/wizard')
@login_required
@admin_required
def wizard():
    """Step-by-step setup wizard."""
    status = get_demo_status()

    if TUNNEL_AVAILABLE and tunnel_manager:
        status = tunnel_manager.get_status().to_dict()

    # Determine current step
    step = 1  # Install cloudflared
    if status['cloudflared_version']:
        step = 2  # Get token from Cloudflare
    if status['state'] not in ('not_installed', 'unconfigured'):
        step = 3  # Configure DNS
    if status['state'] == 'connected':
        step = 4  # Complete

    return render_template(
        'tunnel/wizard.html',
        status=status,
        step=step,
        tunnel_available=TUNNEL_AVAILABLE
    )


@tunnel_bp.route('/install', methods=['POST'])
@login_required
@admin_required
def install():
    """Install cloudflared binary."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        flash('Tunnel manager not available', 'danger')
        return redirect(url_for('tunnel.wizard'))

    success, message = tunnel_manager.install_cloudflared()

    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')

    return redirect(url_for('tunnel.wizard'))


@tunnel_bp.route('/configure', methods=['POST'])
@login_required
@admin_required
def configure():
    """Configure tunnel with token and hostname."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        flash('Tunnel manager not available', 'danger')
        return redirect(url_for('tunnel.wizard'))

    token = request.form.get('token', '').strip()
    hostname = request.form.get('hostname', '').strip()
    auto_start = request.form.get('auto_start') == 'on'

    if not token:
        flash('Tunnel token is required', 'warning')
        return redirect(url_for('tunnel.wizard'))

    if not hostname:
        flash('Hostname is required', 'warning')
        return redirect(url_for('tunnel.wizard'))

    # Basic hostname validation
    if not '.' in hostname or hostname.startswith('.') or hostname.endswith('.'):
        flash('Invalid hostname format', 'warning')
        return redirect(url_for('tunnel.wizard'))

    success, message = tunnel_manager.configure(
        token=token,
        hostname=hostname,
        auto_start=auto_start
    )

    if success:
        flash(message, 'success')
        # Try to start the tunnel
        start_success, start_msg = tunnel_manager.start()
        if start_success:
            flash('Tunnel started successfully!', 'success')
        else:
            flash(f'Tunnel configured but failed to start: {start_msg}', 'warning')
    else:
        flash(message, 'danger')

    return redirect(url_for('tunnel.index'))


@tunnel_bp.route('/start', methods=['POST'])
@login_required
@admin_required
def start():
    """Start the tunnel."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        flash('Tunnel manager not available', 'danger')
        return redirect(url_for('tunnel.index'))

    success, message = tunnel_manager.start()

    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')

    return redirect(url_for('tunnel.index'))


@tunnel_bp.route('/stop', methods=['POST'])
@login_required
@admin_required
def stop():
    """Stop the tunnel."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        flash('Tunnel manager not available', 'danger')
        return redirect(url_for('tunnel.index'))

    success, message = tunnel_manager.stop()

    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')

    return redirect(url_for('tunnel.index'))


@tunnel_bp.route('/restart', methods=['POST'])
@login_required
@admin_required
def restart():
    """Restart the tunnel."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        flash('Tunnel manager not available', 'danger')
        return redirect(url_for('tunnel.index'))

    success, message = tunnel_manager.restart()

    if success:
        flash('Tunnel restarted', 'success')
    else:
        flash(f'Restart failed: {message}', 'danger')

    return redirect(url_for('tunnel.index'))


@tunnel_bp.route('/reset', methods=['POST'])
@login_required
@admin_required
def reset():
    """Clear tunnel configuration."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        flash('Tunnel manager not available', 'danger')
        return redirect(url_for('tunnel.index'))

    success, message = tunnel_manager.clear_config()

    if success:
        flash('Tunnel configuration cleared', 'success')
    else:
        flash(message, 'danger')

    return redirect(url_for('tunnel.wizard'))


@tunnel_bp.route('/test', methods=['POST'])
@login_required
def test():
    """Test tunnel connectivity."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        return jsonify({'success': False, 'message': 'Tunnel manager not available'})

    success, message = tunnel_manager.test_connectivity()

    return jsonify({
        'success': success,
        'message': message
    })


@tunnel_bp.route('/api/status')
@login_required
def api_status():
    """Get tunnel status (for AJAX polling)."""
    if not TUNNEL_AVAILABLE or not tunnel_manager:
        return jsonify(get_demo_status())

    status = tunnel_manager.get_status().to_dict()
    return jsonify(status)
