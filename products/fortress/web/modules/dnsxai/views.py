"""Fortress dnsXai Views - DNS protection."""
from flask import render_template
from flask_login import login_required
from . import dnsxai_bp

@dnsxai_bp.route('/')
@login_required
def index():
    return render_template('dnsxai/index.html')
