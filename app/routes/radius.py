"""Admin UI for the RADIUS simulator: connection settings, per-user MFA, and a
live auth/accounting log. The protocol server itself runs in app.services."""
from flask import Blueprint, render_template, request, redirect, url_for, flash

from app.routes.admin import admin_required
from app.utils.models import db, User
from app.utils.models_aaa import AaaUserAuth, recent_aaa_logs
from app.utils.config_manager import config_manager
from app.utils.activity import record

radius_bp = Blueprint('radius', __name__, url_prefix='/admin/radius')


@radius_bp.route('/')
@admin_required
def config():
    users = User.query.order_by(User.username).all()
    aaa = {a.user_id: a for a in AaaUserAuth.query.all()}
    return render_template('admin/radius/config.html', users=users, aaa=aaa,
                           cfg=config_manager, default_otp=config_manager.AAA_DEFAULT_OTP)


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
    row.otp = otp or config_manager.AAA_DEFAULT_OTP
    db.session.commit()
    record('settings', f"RADIUS MFA {'enabled' if enable else 'disabled'}", target=username)
    flash(f"MFA {'enabled' if enable else 'disabled'} for {username}", 'success')
    return redirect(url_for('radius.config'))


@radius_bp.route('/log')
@admin_required
def log():
    return render_template('admin/radius/log.html', logs=recent_aaa_logs('radius', 150))
