"""
Guardian Authentication Views

PIN-based authentication with bcrypt hashing.
PIN is set during setup.sh and stored in /etc/hookprobe/guardian_auth.json.
"""
import hashlib
import json
import logging
import os
import secrets
import time

from flask import Blueprint, jsonify, request, session, render_template, redirect, url_for

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

AUTH_FILE = '/etc/hookprobe/guardian_auth.json'
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

# Track failed attempts per IP
_failed_attempts = {}


def _load_auth():
    """Load auth config from file."""
    try:
        with open(AUTH_FILE, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None


def _hash_pin(pin, salt=None):
    """Hash a PIN with PBKDF2-SHA256.

    Uses PBKDF2 instead of bcrypt to avoid extra dependency on embedded systems.
    """
    if salt is None:
        salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 100000)
    return salt, derived.hex()


def _verify_pin(pin, stored_salt, stored_hash):
    """Verify a PIN against stored hash."""
    _, derived = _hash_pin(pin, stored_salt)
    return secrets.compare_digest(derived, stored_hash)


def _check_lockout(client_ip):
    """Check if client IP is locked out due to failed attempts."""
    info = _failed_attempts.get(client_ip)
    if not info:
        return False
    if info['count'] >= MAX_ATTEMPTS:
        elapsed = time.time() - info['last_attempt']
        if elapsed < LOCKOUT_SECONDS:
            return True
        # Lockout expired, reset
        del _failed_attempts[client_ip]
    return False


def _record_failure(client_ip):
    """Record a failed login attempt."""
    info = _failed_attempts.get(client_ip, {'count': 0, 'last_attempt': 0})
    info['count'] += 1
    info['last_attempt'] = time.time()
    _failed_attempts[client_ip] = info


def _clear_failures(client_ip):
    """Clear failed attempts on successful login."""
    _failed_attempts.pop(client_ip, None)


def is_auth_configured():
    """Check if authentication has been set up."""
    auth = _load_auth()
    return auth is not None and 'pin_hash' in auth


@auth_bp.route('/login', methods=['GET'])
def login_page():
    """Serve login page."""
    if session.get('authenticated'):
        return redirect('/')
    configured = is_auth_configured()
    return render_template('auth/login.html', configured=configured)


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate with PIN."""
    client_ip = request.remote_addr

    if _check_lockout(client_ip):
        remaining = int(LOCKOUT_SECONDS - (time.time() - _failed_attempts[client_ip]['last_attempt']))
        return jsonify({
            'success': False,
            'error': f'Too many attempts. Try again in {remaining}s'
        }), 429

    data = request.get_json() or {}
    pin = data.get('pin', '')

    if not pin or len(pin) < 4:
        return jsonify({'success': False, 'error': 'PIN required (min 4 digits)'}), 400

    auth = _load_auth()
    if not auth or 'pin_hash' not in auth:
        # First-time setup: set the PIN
        salt, pin_hash = _hash_pin(pin)
        auth_data = {
            'pin_hash': pin_hash,
            'pin_salt': salt,
            'created_at': time.time(),
        }
        try:
            os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
            with open(AUTH_FILE, 'w') as f:
                json.dump(auth_data, f)
            os.chmod(AUTH_FILE, 0o600)
        except IOError as e:
            logger.error("Failed to write auth file: %s", e)
            return jsonify({'success': False, 'error': 'Failed to save PIN'}), 500

        session['authenticated'] = True
        session.permanent = True
        _clear_failures(client_ip)
        return jsonify({'success': True, 'message': 'PIN created and logged in'})

    # Verify PIN
    if _verify_pin(pin, auth['pin_salt'], auth['pin_hash']):
        session['authenticated'] = True
        session.permanent = True
        _clear_failures(client_ip)
        return jsonify({'success': True})

    _record_failure(client_ip)
    attempts_left = MAX_ATTEMPTS - _failed_attempts.get(client_ip, {}).get('count', 0)
    return jsonify({
        'success': False,
        'error': f'Invalid PIN ({max(0, attempts_left)} attempts remaining)'
    }), 401


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Log out."""
    session.clear()
    return jsonify({'success': True})


@auth_bp.route('/status')
def auth_status():
    """Check authentication status."""
    return jsonify({
        'authenticated': bool(session.get('authenticated')),
        'configured': is_auth_configured(),
    })
