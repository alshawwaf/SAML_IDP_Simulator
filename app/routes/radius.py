"""Admin UI for the RADIUS simulator: editable connection settings, per-user
TOTP MFA (authenticator-app enrollment), and a live auth/accounting log. The
protocol server runs in app.services."""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify

from app.routes.admin import admin_required
from app.utils.models import db, User
from app.utils.models_aaa import (
    AaaUserAuth, recent_aaa_logs, get_setting, set_setting,
    ensure_totp_secret, regenerate_totp, totp_info,
)
from app.utils.activity import record

radius_bp = Blueprint('radius', __name__, url_prefix='/admin/radius')

_KEYS = ("radius_secret", "radius_auth_port", "radius_acct_port")


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
    except (ValueError, TypeError) as exc:
        flash(f'Invalid value: {exc}', 'error')
        return redirect(url_for('radius.config'))
    record('settings', 'Updated RADIUS connection settings')
    flash('RADIUS settings saved — secret applies immediately; port changes apply on restart.', 'success')
    return redirect(url_for('radius.config'))


@radius_bp.route('/mfa', methods=['POST'])
@admin_required
def set_mfa():
    username = (request.form.get('username') or '').strip()
    enable = request.form.get('mfa') == 'on'
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('radius.config'))
    row = AaaUserAuth.query.filter_by(user_id=user.id).first()
    if row is None:
        row = AaaUserAuth(user_id=user.id)
        db.session.add(row)
    row.mfa = enable
    db.session.commit()
    if enable:
        ensure_totp_secret(row)  # generate a TOTP secret on first enable
    record('settings', f"RADIUS MFA {'enabled' if enable else 'disabled'}", target=username)
    flash(f"MFA {'enabled' if enable else 'disabled'} for {username}", 'success')
    return redirect(url_for('radius.config'))


@radius_bp.route('/totp/<username>')
@admin_required
def totp(username):
    """Enrollment QR + secret + live code for an MFA-enabled user (admin-only)."""
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"ok": False, "error": "Unknown user"}), 404
    row = AaaUserAuth.query.filter_by(user_id=user.id).first()
    if not row or not row.mfa:
        return jsonify({"ok": False, "error": "MFA not enabled"}), 400
    ensure_totp_secret(row)
    return jsonify({"ok": True, **totp_info(user, row)})


@radius_bp.route('/totp/<username>/regenerate', methods=['POST'])
@admin_required
def totp_regenerate(username):
    user = User.query.filter_by(username=username).first()
    row = AaaUserAuth.query.filter_by(user_id=user.id).first() if user else None
    if not row:
        return jsonify({"ok": False, "error": "Unknown user"}), 404
    regenerate_totp(row)
    record('settings', 'Regenerated TOTP secret', target=username)
    return jsonify({"ok": True})


@radius_bp.route('/log')
@admin_required
def log():
    return render_template('admin/radius/log.html', logs=recent_aaa_logs('radius', 150))
