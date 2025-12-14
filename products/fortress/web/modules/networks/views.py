"""Fortress Networks Views - VLAN configuration."""
from flask import render_template
from flask_login import login_required
from . import networks_bp

@networks_bp.route('/')
@login_required
def index():
    return render_template('networks/index.html')
