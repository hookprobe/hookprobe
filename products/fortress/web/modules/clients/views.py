"""Fortress Clients Views - Device management."""
from flask import render_template
from flask_login import login_required
from . import clients_bp

@clients_bp.route('/')
@login_required
def index():
    return render_template('clients/index.html')
