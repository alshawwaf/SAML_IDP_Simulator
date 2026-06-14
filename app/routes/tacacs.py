"""Admin UI for the TACACS+ simulator: connection settings and a live log.
The protocol server runs in app.services; TACACS+ authenticates demo users with
their directory password (device-admin AAA), so MFA is managed on the RADIUS page."""
from flask import Blueprint, render_template

from app.routes.admin import admin_required
from app.utils.models import User
from app.utils.models_aaa import recent_aaa_logs
from app.utils.config_manager import config_manager

tacacs_bp = Blueprint('tacacs', __name__, url_prefix='/admin/tacacs')


@tacacs_bp.route('/')
@admin_required
def config():
    users = User.query.order_by(User.username).all()
    return render_template('admin/tacacs/config.html', users=users, cfg=config_manager)


@tacacs_bp.route('/log')
@admin_required
def log():
    return render_template('admin/tacacs/log.html', logs=recent_aaa_logs('tacacs', 150))
