"""Fortress Settings Views - System settings, user management."""
from flask import render_template
from flask_login import login_required
from ..auth.decorators import admin_required
from . import settings_bp

@settings_bp.route('/')
@login_required
def index():
    return render_template('settings/index.html')

@settings_bp.route('/users')
@admin_required
def users():
    from ..auth.models import User
    return render_template('settings/users.html', users=User.get_all())
