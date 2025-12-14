"""
Fortress Authentication Views

Supports:
- Local authentication (username/password)
- Logto IAM (OAuth2/OIDC) if configured
"""

import secrets
import requests
from urllib.parse import urlencode

from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user

from . import auth_bp
from .models import User


def is_logto_enabled():
    """Check if Logto IAM is configured and enabled."""
    return (
        current_app.config.get('LOGTO_ENABLED', False) and
        current_app.config.get('LOGTO_ENDPOINT') and
        current_app.config.get('LOGTO_APP_ID')
    )


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    # Ensure admin exists on first access
    User.ensure_admin_exists()

    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    # Check if Logto is enabled
    logto_enabled = is_logto_enabled()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        if not username or not password:
            flash('Please enter username and password.', 'warning')
            return render_template('auth/login.html', logto_enabled=logto_enabled)

        user = User.authenticate(username, password)
        if user:
            login_user(user, remember=bool(remember))
            flash(f'Welcome back, {user.display_name or user.id}!', 'success')

            # Redirect to requested page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html', logto_enabled=logto_enabled)


# ============================================================
# Logto OAuth2/OIDC Routes
# ============================================================

@auth_bp.route('/login/logto')
def login_logto():
    """Initiate Logto OAuth2 login flow."""
    if not is_logto_enabled():
        flash('Logto authentication is not configured.', 'warning')
        return redirect(url_for('auth.login'))

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    # Store the next URL
    next_page = request.args.get('next', url_for('dashboard.index'))
    session['oauth_next'] = next_page

    # Build authorization URL
    logto_endpoint = current_app.config['LOGTO_ENDPOINT'].rstrip('/')
    params = {
        'client_id': current_app.config['LOGTO_APP_ID'],
        'redirect_uri': current_app.config['LOGTO_REDIRECT_URI'],
        'response_type': 'code',
        'scope': 'openid profile email',
        'state': state,
    }

    auth_url = f"{logto_endpoint}/oidc/auth?{urlencode(params)}"
    return redirect(auth_url)


@auth_bp.route('/callback')
def callback():
    """Handle Logto OAuth2 callback."""
    if not is_logto_enabled():
        flash('Logto authentication is not configured.', 'warning')
        return redirect(url_for('auth.login'))

    # Verify state
    state = request.args.get('state')
    if state != session.pop('oauth_state', None):
        flash('Invalid authentication state. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

    # Check for errors
    error = request.args.get('error')
    if error:
        flash(f'Authentication failed: {error}', 'danger')
        return redirect(url_for('auth.login'))

    # Exchange code for tokens
    code = request.args.get('code')
    if not code:
        flash('No authorization code received.', 'danger')
        return redirect(url_for('auth.login'))

    try:
        logto_endpoint = current_app.config['LOGTO_ENDPOINT'].rstrip('/')
        token_response = requests.post(
            f"{logto_endpoint}/oidc/token",
            data={
                'grant_type': 'authorization_code',
                'client_id': current_app.config['LOGTO_APP_ID'],
                'client_secret': current_app.config['LOGTO_APP_SECRET'],
                'redirect_uri': current_app.config['LOGTO_REDIRECT_URI'],
                'code': code,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )
        token_response.raise_for_status()
        tokens = token_response.json()

        # Get user info
        userinfo_response = requests.get(
            f"{logto_endpoint}/oidc/me",
            headers={'Authorization': f"Bearer {tokens['access_token']}"},
            timeout=10
        )
        userinfo_response.raise_for_status()
        userinfo = userinfo_response.json()

        # Find or create user
        user_id = userinfo.get('sub')
        email = userinfo.get('email', '')
        name = userinfo.get('name', email.split('@')[0] if email else user_id)

        user = User.get(user_id)
        if not user:
            # Create new user from Logto
            user = User(
                id=user_id,
                role='viewer',  # Default role for new SSO users
                display_name=name,
                email=email,
                auth_provider='logto'
            )
            user.save()

        login_user(user, remember=True)
        flash(f'Welcome, {user.display_name or user.id}!', 'success')

        # Redirect to stored next URL
        next_page = session.pop('oauth_next', url_for('dashboard.index'))
        return redirect(next_page)

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Logto auth error: {e}")
        flash('Authentication service unavailable. Please try local login.', 'danger')
        return redirect(url_for('auth.login'))
    except Exception as e:
        current_app.logger.error(f"Logto auth error: {e}")
        flash('Authentication failed. Please try again.', 'danger')
        return redirect(url_for('auth.login'))


@auth_bp.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    """View/edit user profile."""
    return render_template('auth/profile.html', user=current_user)


@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change current user's password."""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('auth.profile'))

    if len(new_password) < 8:
        flash('New password must be at least 8 characters.', 'warning')
        return redirect(url_for('auth.profile'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'warning')
        return redirect(url_for('auth.profile'))

    # Update password
    user = User.get(current_user.id)
    user.set_password(new_password)
    user.save()

    flash('Password changed successfully.', 'success')
    return redirect(url_for('auth.profile'))
