"""
Fortress Authentication Decorators
"""

from functools import wraps
from flask import flash, redirect, url_for, abort
from flask_login import current_user


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if not current_user.is_admin:
            flash('You need admin privileges to access this page.', 'danger')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def operator_required(f):
    """Decorator to require operator role or higher."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if not current_user.is_operator:
            flash('You need operator privileges to access this page.', 'danger')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
