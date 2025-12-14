"""Fortress Security Views - QSecBit, threats, layer stats."""
from flask import render_template
from flask_login import login_required
from . import security_bp

@security_bp.route('/')
@login_required
def index():
    return render_template('security/index.html')
