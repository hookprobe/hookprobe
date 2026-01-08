"""
Fortress Authentication Views

Simple local authentication for small business (max 5 users).
Uses bcrypt password hashing and Flask-Login sessions.
"""

import urllib.parse

from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user

from . import auth_bp
from .models import User, UserRole, MAX_USERS
from .decorators import admin_required


def is_safe_redirect_url(target: str) -> bool:
    """
    Validate redirect target to prevent open redirect vulnerabilities.

    Security: Blocks protocol-relative URLs, absolute URLs, javascript: URLs,
    and only allows paths starting with a single forward slash.
    """
    if not target or not isinstance(target, str):
        return False

    # Block javascript: URLs
    if target.lower().startswith('javascript:'):
        return False

    # Parse the target URL
    parsed = urllib.parse.urlparse(target)

    # Block URLs with scheme (http://, https://, etc.) or netloc (//evil.com)
    if parsed.scheme or parsed.netloc:
        return False

    # Only allow paths starting with single / but not //
    if not parsed.path.startswith('/') or parsed.path.startswith('//'):
        return False

    return True


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    # Ensure admin exists on first access
    User.ensure_admin_exists()

    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        if not username or not password:
            flash('Please enter username and password.', 'warning')
            return render_template('auth/login.html')

        user = User.authenticate(username, password)
        if user:
            login_user(user, remember=bool(remember))
            flash(f'Welcome back, {user.display_name or user.id}!', 'success')

            # Security: Validate redirect target to prevent open redirect attacks
            next_page = request.args.get('next')
            if next_page and is_safe_redirect_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html')


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
    # Reload user from storage to get latest data
    user = User.get(current_user.id)
    return render_template(
        'auth/profile.html',
        user=user,
        user_count=User.user_count(),
        max_users=MAX_USERS
    )


@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change current user's password."""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    # Get fresh user from storage
    user = User.get(current_user.id)
    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('auth.logout'))

    if not user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('auth.profile'))

    if len(new_password) < 8:
        flash('New password must be at least 8 characters.', 'warning')
        return redirect(url_for('auth.profile'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'warning')
        return redirect(url_for('auth.profile'))

    # Update password
    user.set_password(new_password)
    if user.save():
        flash('Password changed successfully.', 'success')
    else:
        flash('Failed to save password. Please try again.', 'danger')

    return redirect(url_for('auth.profile'))


@auth_bp.route('/update-display-name', methods=['POST'])
@login_required
def update_display_name():
    """Update user's display name."""
    display_name = request.form.get('display_name', '').strip()

    # Sanitize display name (max 50 chars)
    if display_name:
        display_name = display_name[:50]

    # Get fresh user from storage
    user = User.get(current_user.id)
    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('auth.logout'))

    user.display_name = display_name if display_name else None

    if user.save():
        if display_name:
            flash(f'Display name updated to "{display_name}".', 'success')
        else:
            flash('Display name cleared.', 'info')
    else:
        flash('Failed to save display name. Please try again.', 'danger')

    return redirect(url_for('auth.profile'))


# =============================================================================
# USER MANAGEMENT API (Admin only)
# =============================================================================

@auth_bp.route('/api/users', methods=['GET'])
@login_required
@admin_required
def api_list_users():
    """Get all users."""
    users = User.get_all()
    return jsonify({
        'success': True,
        'users': [u.to_dict() for u in users],
        'count': len(users),
        'max_users': MAX_USERS,
        'can_create': User.can_create_user()
    })


@auth_bp.route('/api/users', methods=['POST'])
@login_required
@admin_required
def api_create_user():
    """Create a new user."""
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', UserRole.VIEWER.value)
    email = data.get('email', '').strip() or None
    display_name = data.get('display_name', '').strip() or None

    # Validation
    if not username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400

    if len(username) < 3 or len(username) > 20:
        return jsonify({'success': False, 'error': 'Username must be 3-20 characters'}), 400

    if not username.isalnum():
        return jsonify({'success': False, 'error': 'Username must be alphanumeric'}), 400

    if not password or len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400

    if role not in [r.value for r in UserRole]:
        return jsonify({'success': False, 'error': 'Invalid role'}), 400

    if User.get(username):
        return jsonify({'success': False, 'error': 'Username already exists'}), 400

    if not User.can_create_user():
        return jsonify({'success': False, 'error': f'Maximum {MAX_USERS} users allowed'}), 400

    # Create user
    user = User.create(
        username=username,
        password=password,
        role=role,
        email=email,
        display_name=display_name
    )

    if user:
        return jsonify({
            'success': True,
            'message': f'User "{username}" created successfully',
            'user': user.to_dict()
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to create user'}), 500


@auth_bp.route('/api/users/<user_id>', methods=['GET'])
@login_required
@admin_required
def api_get_user(user_id):
    """Get a specific user."""
    user = User.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    return jsonify({'success': True, 'user': user.to_dict()})


@auth_bp.route('/api/users/<user_id>', methods=['PUT'])
@login_required
@admin_required
def api_update_user(user_id):
    """Update a user."""
    user = User.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    # Update fields
    if 'display_name' in data:
        user.display_name = data['display_name'].strip()[:50] if data['display_name'] else None

    if 'email' in data:
        user.email = data['email'].strip() if data['email'] else None

    if 'role' in data:
        new_role = data['role']
        if new_role not in [r.value for r in UserRole]:
            return jsonify({'success': False, 'error': 'Invalid role'}), 400

        # Prevent demoting the last admin
        if user.role == UserRole.ADMIN.value and new_role != UserRole.ADMIN.value:
            admin_count = sum(1 for u in User.get_all() if u.role == UserRole.ADMIN.value)
            if admin_count <= 1:
                return jsonify({'success': False, 'error': 'Cannot remove the last admin'}), 400

        user.role = new_role

    if 'is_active' in data:
        # Prevent deactivating the last admin
        if user.role == UserRole.ADMIN.value and not data['is_active']:
            active_admin_count = sum(1 for u in User.get_all()
                                     if u.role == UserRole.ADMIN.value and u.is_active)
            if active_admin_count <= 1:
                return jsonify({'success': False, 'error': 'Cannot deactivate the last admin'}), 400

        user.is_active = bool(data['is_active'])

    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        user.set_password(data['password'])

    if user.save():
        return jsonify({
            'success': True,
            'message': f'User "{user_id}" updated successfully',
            'user': user.to_dict()
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to save user'}), 500


@auth_bp.route('/api/users/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def api_delete_user(user_id):
    """Delete a user."""
    # Prevent self-deletion
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400

    user = User.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    # Prevent deleting the last admin
    if user.role == UserRole.ADMIN.value:
        admin_count = sum(1 for u in User.get_all() if u.role == UserRole.ADMIN.value)
        if admin_count <= 1:
            return jsonify({'success': False, 'error': 'Cannot delete the last admin'}), 400

    if User.delete(user_id):
        return jsonify({
            'success': True,
            'message': f'User "{user_id}" deleted successfully'
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to delete user'}), 500
