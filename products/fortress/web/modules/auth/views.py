"""
Fortress Authentication Views

Simple local authentication for small business (max 5 users).
Uses bcrypt password hashing and Flask-Login sessions.
"""

from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from . import auth_bp
from .models import User, MAX_USERS


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

            # Redirect to requested page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
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
    return render_template(
        'auth/profile.html',
        user=current_user,
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
