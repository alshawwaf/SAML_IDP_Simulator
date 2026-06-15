"""Admin UI for the TACACS+ simulator: editable connection settings and a live
log. The protocol server runs in app.services; TACACS+ authenticates demo users
with their directory password (device-admin AAA), so MFA is managed on the
RADIUS page."""
from flask import Blueprint, render_template, request, redirect, url_for, flash

from app.routes.admin import admin_required
from app.utils.models import User
from app.utils.config_manager import config_manager
from app.utils.models_aaa import recent_aaa_logs, get_setting, set_setting, public_endpoint
from app.utils.activity import record

tacacs_bp = Blueprint('tacacs', __name__, url_prefix='/admin/tacacs')

_KEYS = ("tacacs_secret", "tacacs_port")


@tacacs_bp.route('/')
@admin_required
def config():
    users = User.query.order_by(User.username).all()
    s = {k: get_setting(k) for k in _KEYS}
    host, source = public_endpoint(detect=False)  # instant; JS fills if unknown
    return render_template('admin/tacacs/config.html', users=users, s=s,
                           endpoint_host=host, endpoint_source=source,
                           tacacs_public_port=config_manager.TACACS_PUBLIC_PORT)


@tacacs_bp.route('/settings', methods=['POST'])
@admin_required
def save_settings():
    try:
        secret = (request.form.get('tacacs_secret') or '').strip()
        if secret:  # blank = keep current
            set_setting('tacacs_secret', secret)
        set_setting('tacacs_port', request.form.get('tacacs_port'))
    except (ValueError, TypeError) as exc:
        flash(f'Invalid value: {exc}', 'error')
        return redirect(url_for('tacacs.config'))
    record('settings', 'Updated TACACS+ connection settings')
    flash('TACACS+ settings saved — secret applies immediately; port change applies on restart.', 'success')
    return redirect(url_for('tacacs.config'))


@tacacs_bp.route('/log')
@admin_required
def log():
    return render_template('admin/tacacs/log.html', logs=recent_aaa_logs('tacacs', 150))
