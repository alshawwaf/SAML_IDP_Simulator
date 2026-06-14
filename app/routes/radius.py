"""Admin UI for the RADIUS simulator: editable connection settings, per-user
MFA, and a live auth/accounting log. The protocol server runs in app.services."""
from flask import Blueprint, render_template, request, redirect, url_for, flash

from app.routes.admin import admin_required
from app.utils.models import db, User
from app.utils.models_aaa import AaaUserAuth, recent_aaa_logs, get_setting, set_setting
from app.utils.activity import record

radius_bp = Blueprint('radius', __name__, url_prefix='/admin/radius')

_KEYS = ("radius_secret", "radius_auth_port", "radius_acct_port", "default_otp")


@radius_bp.route('/')
@admin_required
def config():
    users = User.query.order_by(User.username).all()
    aaa = {a.user_id: a for a in AaaUserAuth.query.all()}
    s = {k: get_setting(k) for k in _KEYS}
    return render_template('admin/radius/config.html', users=users, aaa=aaa, s=s)


@radius_bp.route('/settings', methods=['POST'])
@admin_required
def save_settings():
    try:
        secret = (request.form.get('radius_secret') or '').strip()
        if secret:  # blank = keep current
            set_setting('radius_secret', secret)
        set_setting('radius_auth_port', request.form.get('radius_auth_port'))
        set_setting('radius_acct_port', request.form.get('radius_acct_port'))
        set_setting('default_otp', (request.form.get('default_otp') or '').strip() or '123456')
    except (ValueError, TypeError) as exc:
        flash(f'Invalid value: {exc}', 'error')
        return redirect(url_for('radius.config'))
    record('settings', 'Updated RADIUS connection settings')
    flash('RADIUS settings saved — secret/OTP apply immediately; port changes apply on restart.', 'success')
    return redirect(url_for('radius.config'))


@radius_bp.route('/mfa', methods=['POST'])
@admin_required
def set_mfa():
    username = (request.form.get('username') or '').strip()
    enable = request.form.get('mfa') == 'on'
    otp = (request.form.get('otp') or '').strip()
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('radius.config'))
    row = AaaUserAuth.query.filter_by(user_id=user.id).first()
    if row is None:
        row = AaaUserAuth(user_id=user.id)
        db.session.add(row)
    row.mfa = enable
    row.otp = otp or get_setting('default_otp')
    db.session.commit()
    record('settings', f"RADIUS MFA {'enabled' if enable else 'disabled'}", target=username)
    flash(f"MFA {'enabled' if enable else 'disabled'} for {username}", 'success')
    return redirect(url_for('radius.config'))


@radius_bp.route('/log')
@admin_required
def log():
    return render_template('admin/radius/log.html', logs=recent_aaa_logs('radius', 150))
