"""Fortress Reports Views - Business reports."""
from flask import render_template
from flask_login import login_required
from . import reports_bp

@reports_bp.route('/')
@login_required
def index():
    return render_template('reports/index.html')
