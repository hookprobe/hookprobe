"""
Guardian Authentication Views

PIN-based authentication with PBKDF2-SHA256 hashing.
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

# Track failed attempts per IP (thread-safe)
_failed_attempts = {}
_failed_attempts_lock = __import__('threading').Lock()


def _get_client_ip():
    """Get real client IP, accounting for WAF/reverse proxy."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    real_ip = request.headers.get('X-Real-IP', '')
    if real_ip:
        return real_ip.strip()
    return request.remote_addr


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
    """Check if client IP is locked out. Returns (locked, remaining_seconds, attempts_used)."""
    with _failed_attempts_lock:
        info = _failed_attempts.get(client_ip)
        if not info:
            return False, 0, 0
        if info['count'] >= MAX_ATTEMPTS:
            elapsed = time.time() - info['last_attempt']
            if elapsed < LOCKOUT_SECONDS:
                remaining = int(LOCKOUT_SECONDS - elapsed)
                return True, remaining, info['count']
            # Lockout expired, reset
            del _failed_attempts[client_ip]
            return False, 0, 0
        return False, 0, info['count']


def _record_failure(client_ip):
    """Record a failed login attempt. Returns updated count."""
    with _failed_attempts_lock:
        info = _failed_attempts.get(client_ip, {'count': 0, 'last_attempt': 0})
        info['count'] += 1
        info['last_attempt'] = time.time()
        _failed_attempts[client_ip] = info
        return info['count']


def _clear_failures(client_ip):
    """Clear failed attempts on successful login."""
    with _failed_attempts_lock:
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
    client_ip = _get_client_ip()

    locked, remaining, attempts = _check_lockout(client_ip)
    if locked:
        logger.warning("Locked out IP %s tried login (%d attempts)", client_ip, attempts)
        return jsonify({
            'success': False,
            'locked': True,
            'remaining': remaining,
            'error': f'Too many attempts. Try again in {remaining}s'
        }), 429

    data = request.get_json() or {}
    pin = data.get('pin', '')

    if not pin or len(pin) < 4:
        return jsonify({'success': False, 'error': 'PIN required (min 4 digits)'}), 400

    auth = _load_auth()
    if not auth or 'pin_hash' not in auth:
        # First-time setup: just set the PIN
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
        logger.info("Successful login from %s", client_ip)
        return jsonify({'success': True})

    count = _record_failure(client_ip)
    attempts_left = max(0, MAX_ATTEMPTS - count)
    logger.warning("Failed login from %s (attempt %d/%d)", client_ip, count, MAX_ATTEMPTS)

    if attempts_left == 0:
        return jsonify({
            'success': False,
            'locked': True,
            'remaining': LOCKOUT_SECONDS,
            'error': f'Too many attempts. Locked for {LOCKOUT_SECONDS // 60} minutes'
        }), 429

    return jsonify({
        'success': False,
        'attempts_left': attempts_left,
        'error': f'Invalid PIN ({attempts_left} attempts remaining)'
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
