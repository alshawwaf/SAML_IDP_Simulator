from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app.utils.models import db, User, ServiceProvider
from app.utils.models_scim import ScimGroup, ScimGroupMember
from app.utils.config_manager import config_manager
from app.utils.extensions import limiter
from app.utils.activity import record
from werkzeug.security import generate_password_hash
import json

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    """Decorator to require admin login"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function


def _ids_from_form(field):
    """Parse a repeated integer form field (e.g. checkbox group) into a list of ints."""
    return [int(x) for x in request.form.getlist(field) if x.isdigit()]


def _reconcile_group_members(group, desired_user_ids):
    """Make `group`'s membership exactly `desired_user_ids` (User.id values).
    Adds missing links, removes the rest. Caller commits."""
    desired = set(desired_user_ids)
    current = {m.user_id: m for m in ScimGroupMember.query.filter_by(group_pk=group.id).all()}
    for uid in desired - set(current):
        if User.query.get(uid):
            db.session.add(ScimGroupMember(group_pk=group.id, user_id=uid))
    for uid, member in current.items():
        if uid not in desired:
            db.session.delete(member)


def _reconcile_user_groups(user, desired_group_pks):
    """Make `user`'s memberships exactly `desired_group_pks` (ScimGroup.id values).
    The user-side mirror of _reconcile_group_members. Caller commits."""
    desired = set(desired_group_pks)
    current = {m.group_pk: m for m in ScimGroupMember.query.filter_by(user_id=user.id).all()}
    for gpk in desired - set(current):
        if ScimGroup.query.get(gpk):
            db.session.add(ScimGroupMember(group_pk=gpk, user_id=user.id))
    for gpk, member in current.items():
        if gpk not in desired:
            db.session.delete(member)

@admin_bp.route('/')
@admin_required
def dashboard():
    return render_template(
        'admin/dashboard.html',
        user_count=User.query.count(),
        group_count=ScimGroup.query.count(),
        sp_count=ServiceProvider.query.count(),
        config=config_manager.get_all_config(),
    )

@admin_bp.route('/settings')
@admin_required
def settings():
    # Settings moved into the navbar account menu (Change Password / Reset /
    # Sign out) and the IDP Config page. Kept as a redirect so old links work.
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/idp-config')
@admin_required
def idp_config():
    return render_template('admin/idp_config.html', config=config_manager.get_all_config())

# ==================== USER MANAGEMENT ====================

@admin_bp.route('/users')
@admin_required
def user_management():
    users = User.query.all()
    user_fields = User.get_editable_user_fields()
    # Groups available to assign as membership in the add/edit-user modals.
    all_groups = ScimGroup.query.order_by(ScimGroup.display_name).all()
    return render_template('admin/user_management.html', users=users,
                           user_fields=user_fields, all_groups=all_groups)

@admin_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    first_name = request.form.get('first_name', '')
    last_name = request.form.get('last_name', '')

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('admin.user_management'))

    if User.query.filter_by(email=email).first():
        flash('Email already exists', 'error')
        return redirect(url_for('admin.user_management'))

    user = User(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.flush()  # populate user.id for membership links
    # Group membership comes from the multi-select (first-class groups), not the
    # retired free-text field.
    _reconcile_user_groups(user, _ids_from_form('group_pks'))
    db.session.commit()
    record('user', 'Created user', target=username,
           detail={'email': email, 'groups': user.group_names})
    flash('User added successfully', 'success')
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/users/<username>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    user_fields = User.get_editable_user_fields()
    if request.method == 'POST':
        user.email = request.form.get('email', user.email)
        user.first_name = request.form.get('first_name', user.first_name)
        user.last_name = request.form.get('last_name', user.last_name)
        if request.form.get('password'):
            user.set_password(request.form.get('password'))
        _reconcile_user_groups(user, _ids_from_form('group_pks'))
        db.session.commit()
        record('user', 'Updated user', target=username)
        flash('User updated', 'success')
        return redirect(url_for('admin.user_management'))
    all_groups = ScimGroup.query.order_by(ScimGroup.display_name).all()
    member_group_pks = {m.group_pk for m in user.scim_memberships}
    return render_template('admin/edit_user.html', user=user, user_fields=user_fields,
                           all_groups=all_groups, member_group_pks=member_group_pks)

@admin_bp.route('/users/<username>/delete')
@admin_required
def delete_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    db.session.delete(user)
    db.session.commit()
    record('user', 'Deleted user', target=username)
    flash('User deleted', 'success')
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/api/users/<username>', methods=['GET'])
@admin_required
def get_user_api(username):
    """API endpoint to get user data for modal"""
    user = User.query.filter_by(username=username).first_or_404()
    return jsonify({
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name or '',
        'last_name': user.last_name or '',
        # Group memberships drive the edit modal's checkbox state.
        'group_pks': [m.group_pk for m in user.scim_memberships],
        'is_admin': user.is_admin
    })

@admin_bp.route('/update_user', methods=['POST'])
@admin_required
def update_user():
    """API endpoint to update user from modal"""
    username = request.form.get('username')
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    user.email = request.form.get('email', user.email)
    user.first_name = request.form.get('first_name', user.first_name)
    user.last_name = request.form.get('last_name', user.last_name)
    _reconcile_user_groups(user, _ids_from_form('group_pks'))

    db.session.commit()
    record('user', 'Updated user', target=username)
    return jsonify({'success': True})

@admin_bp.route('/reset_password', methods=['POST'])
@admin_required
def reset_password():
    """Reset user password"""
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not username or not new_password:
        flash('Username and password are required', 'error')
        return redirect(url_for('admin.user_management'))
    
    if new_password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('admin.user_management'))
    
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin.user_management'))
    
    user.set_password(new_password)
    db.session.commit()
    record('user', 'Reset password', target=username)
    flash(f'Password reset successfully for {username}', 'success')
    return redirect(url_for('admin.user_management'))

# ==================== GROUP MANAGEMENT ====================
# Groups are first-class directory objects (app.utils.models_scim.ScimGroup):
# each has a stable group_id UUID (Entra objectId / Okta id equivalent) and a
# member list. Membership feeds the SAML group_names/group_ids claim sources, so
# a whole group can be granted access at an SP (e.g. SmartConsole). These are the
# same entities SCIM provisions in/out, so admin-created groups push to Harmony
# and SCIM-pushed groups appear here. Always available (not behind the SCIM gate).

@admin_bp.route('/groups')
@admin_required
def group_management():
    groups = ScimGroup.query.order_by(ScimGroup.display_name).all()
    users = User.query.order_by(User.username).all()
    return render_template('admin/group_management.html', groups=groups, users=users)

@admin_bp.route('/groups/add', methods=['POST'])
@admin_required
def add_group():
    display_name = (request.form.get('display_name') or '').strip()
    description = (request.form.get('description') or '').strip() or None
    if not display_name:
        flash('Group name is required', 'error')
        return redirect(url_for('admin.group_management'))
    if ScimGroup.query.filter_by(display_name=display_name).first():
        flash('A group with that name already exists', 'error')
        return redirect(url_for('admin.group_management'))

    group = ScimGroup(display_name=display_name, description=description)
    db.session.add(group)
    db.session.flush()  # populate group.id for membership links
    _reconcile_group_members(group, _ids_from_form('member_user_ids'))
    db.session.commit()
    record('group', 'Created group', target=display_name,
           detail={'group_id': group.group_id, 'members': len(group.members)})
    flash(f'Group "{display_name}" created', 'success')
    return redirect(url_for('admin.group_management'))

@admin_bp.route('/api/groups/<int:group_pk>', methods=['GET'])
@admin_required
def get_group_api(group_pk):
    """Group data for the edit modal."""
    group = ScimGroup.query.get_or_404(group_pk)
    return jsonify({
        'id': group.id,
        'group_id': group.group_id,
        'display_name': group.display_name,
        'description': group.description or '',
        'external_id': group.external_id or '',
        'member_user_ids': [m.user_id for m in group.members],
    })

@admin_bp.route('/update_group', methods=['POST'])
@admin_required
def update_group():
    """Update a group from the edit modal (rename, description, membership)."""
    group_pk = request.form.get('group_pk', '')
    group = ScimGroup.query.get(int(group_pk)) if group_pk.isdigit() else None
    if not group:
        return jsonify({'success': False, 'error': 'Group not found'}), 404

    new_name = (request.form.get('display_name') or '').strip()
    if not new_name:
        return jsonify({'success': False, 'error': 'Group name is required'}), 400
    if ScimGroup.query.filter(ScimGroup.display_name == new_name, ScimGroup.id != group.id).first():
        return jsonify({'success': False, 'error': 'A group with that name already exists'}), 409

    group.display_name = new_name
    group.description = (request.form.get('description') or '').strip() or None
    _reconcile_group_members(group, _ids_from_form('member_user_ids'))
    db.session.commit()
    record('group', 'Updated group', target=new_name)
    return jsonify({'success': True})

@admin_bp.route('/groups/<int:group_pk>/delete')
@admin_required
def delete_group(group_pk):
    group = ScimGroup.query.get_or_404(group_pk)
    name = group.display_name
    # Cascade drops ScimGroupMember rows; the SCIM push-log FK is ondelete=SET NULL.
    db.session.delete(group)
    db.session.commit()
    record('group', 'Deleted group', target=name)
    flash(f'Group "{name}" deleted', 'success')
    return redirect(url_for('admin.group_management'))

# ==================== SERVICE PROVIDER MANAGEMENT ====================

@admin_bp.route('/service-providers')
@admin_required
def list_sps():
    sps = ServiceProvider.query.all()
    user_fields = User.get_editable_user_fields()
    return render_template('admin/sp_list.html', sps=sps, user_fields=user_fields)

@admin_bp.route('/service-providers/add', methods=['POST'])
@admin_required
def create_sp():
    name = request.form.get('name')
    entity_id = request.form.get('entity_id')
    acs_url = request.form.get('acs_url')
    
    # Parse attribute mappings from form
    attr_map = []
    i = 0
    while f'claim_name_{i}' in request.form:
        claim_name = request.form.get(f'claim_name_{i}')
        claim_value = request.form.get(f'claim_value_{i}')
        if claim_name and claim_value:
            attr_map.append({'claim': claim_name, 'value': claim_value})
        i += 1
    
    if ServiceProvider.query.filter_by(entity_id=entity_id).first():
        flash('Service Provider with this Entity ID already exists', 'error')
        return redirect(url_for('admin.list_sps'))
    
    sp = ServiceProvider(
        name=name,
        entity_id=entity_id,
        acs_url=acs_url,
        attr_map=attr_map
    )
    db.session.add(sp)
    db.session.commit()
    record('service_provider', 'Created Service Provider', target=name, detail={'entity_id': entity_id, 'acs_url': acs_url})
    flash('Service Provider added successfully', 'success')
    return redirect(url_for('admin.list_sps'))

@admin_bp.route('/service-providers/<int:sp_id>/edit', methods=['POST'])
@admin_required
def edit_sp(sp_id):
    sp = ServiceProvider.query.get_or_404(sp_id)
    
    sp.name = request.form.get('name', sp.name)
    sp.entity_id = request.form.get('entity_id', sp.entity_id)
    sp.acs_url = request.form.get('acs_url', sp.acs_url)
    
    # Parse attribute mappings
    attr_map = []
    i = 0
    while f'claim_name_{i}' in request.form:
        claim_name = request.form.get(f'claim_name_{i}')
        claim_value = request.form.get(f'claim_value_{i}')
        if claim_name and claim_value:
            attr_map.append({'claim': claim_name, 'value': claim_value})
        i += 1
    sp.attr_map = attr_map
    
    db.session.commit()
    record('service_provider', 'Updated Service Provider', target=sp.name)
    flash('Service Provider updated successfully', 'success')
    return redirect(url_for('admin.list_sps'))

@admin_bp.route('/service-providers/<int:sp_id>/delete')
@admin_required
def delete_sp(sp_id):
    sp = ServiceProvider.query.get_or_404(sp_id)
    sp_name = sp.name
    db.session.delete(sp)
    db.session.commit()
    record('service_provider', 'Deleted Service Provider', target=sp_name)
    flash('Service Provider deleted successfully', 'success')
    return redirect(url_for('admin.list_sps'))

@admin_bp.route('/api/service-providers/<int:sp_id>', methods=['GET'])
@admin_required
def get_sp_api(sp_id):
    """API endpoint to get SP data for modal"""
    sp = ServiceProvider.query.get_or_404(sp_id)
    return jsonify({
        'id': sp.id,
        'name': sp.name or '',
        'entity_id': sp.entity_id,
        'acs_url': sp.acs_url,
        'attr_map': sp.attr_map or []
    })

@admin_bp.route('/api/service-providers/<int:sp_id>/xml', methods=['GET'])
@admin_required
def get_sp_xml(sp_id):
    """API endpoint to generate SP metadata XML"""
    from flask import Response
    sp = ServiceProvider.query.get_or_404(sp_id)
    
    # Generate SP metadata XML
    nameid_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    
    attr_statements = ""
    if sp.attr_map:
        attr_statements = "\n".join([
            f'        <md:RequestedAttribute Name="http://schemas.xmlsoap.org/claims/{attr["claim"]}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="false"/>'
            for attr in sp.attr_map
        ])
    
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{sp.entity_id}">
    <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>{nameid_format}</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{sp.acs_url}"
                                     index="0" isDefault="true"/>
        <md:AttributeConsumingService index="0">
            <md:ServiceName xml:lang="en">{sp.name or 'Service Provider'}</md:ServiceName>
{attr_statements}
        </md:AttributeConsumingService>
    </md:SPSSODescriptor>
</md:EntityDescriptor>'''
    
    return Response(xml, mimetype='application/xml')

# ==================== AUTH ====================

@admin_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    from app.utils.admin_password import verify_admin_password
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if username == config_manager.ADMIN_USERNAME and verify_admin_password(password):
            session['admin_logged_in'] = True
            record('auth', 'Admin login', target=username)
            return redirect(url_for('admin.dashboard'))
        record('auth', 'Failed admin login', target=username, status='error', actor=username or 'unknown')
        flash('Invalid credentials', 'error')
        # Echo the submitted username back so the operator can see exactly what
        # was sent (catches password-manager autofilling the wrong username).
        return render_template('admin/login.html', username_value=username)

    # GET: pre-fill the expected admin username so there's no ambiguity.
    return render_template('admin/login.html', username_value=config_manager.ADMIN_USERNAME)

@admin_bp.route('/logout')
def logout():
    record('auth', 'Admin logout')
    session.pop('admin_logged_in', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin.login'))


@admin_bp.route('/toggle-scim', methods=['POST'])
@admin_required
def toggle_scim():
    """Enable/disable SCIM provisioning at runtime from the dashboard."""
    if config_manager.SCIM_FORCED_OFF:
        flash('SCIM is forced off by the ENABLE_SCIM=false environment variable.', 'error')
        return redirect(request.referrer or url_for('admin.dashboard'))
    enable = request.form.get('enable') == 'true'
    config_manager.set_scim_enabled(enable)
    record('scim', f"SCIM provisioning {'enabled' if enable else 'disabled'}", status='info')
    flash(f"SCIM provisioning {'enabled' if enable else 'disabled'}.", 'success')
    return redirect(request.referrer or url_for('admin.dashboard'))


@admin_bp.route('/activity')
@admin_required
def activity_log():
    """App-wide audit log — paginated, filterable by category and status."""
    from app.utils.models import ActivityLog
    page = max(1, request.args.get('page', 1, type=int))
    per_page = 50
    category = request.args.get('category') or None
    status = request.args.get('status') or None
    q = ActivityLog.query.order_by(ActivityLog.id.desc())
    if category:
        q = q.filter_by(category=category)
    if status:
        q = q.filter_by(status=status)
    total = q.count()
    entries = q.offset((page - 1) * per_page).limit(per_page).all()
    return render_template(
        'admin/activity_log.html',
        entries=entries, total=total, page=page, per_page=per_page,
        categories=['auth', 'user', 'group', 'service_provider', 'scim', 'saml', 'settings'],
        filter_category=category, filter_status=status,
    )


@admin_bp.route('/activity/<int:entry_id>')
@admin_required
def activity_detail(entry_id):
    from app.utils.models import ActivityLog
    entry = ActivityLog.query.get_or_404(entry_id)
    return render_template('admin/activity_detail.html', entry=entry)


@admin_bp.route('/change-admin-password', methods=['POST'])
@admin_required
def change_admin_password():
    """Persist a new admin portal password (overrides the env/default)."""
    from app.utils.admin_password import (
        set_admin_password, verify_admin_password, reset_to_default,
    )
    action = request.form.get('action', 'change')

    if action == 'reset':
        reset_to_default()
        record('settings', 'Reset admin password to env/default', status='info')
        flash('Admin password reverted to env/default.', 'success')
        return redirect(request.referrer or url_for('admin.dashboard'))

    current = request.form.get('current_password') or ''
    new_pw = request.form.get('new_password') or ''
    confirm = request.form.get('confirm_password') or ''

    if not verify_admin_password(current):
        flash('Current password is incorrect.', 'error')
        return redirect(request.referrer or url_for('admin.dashboard'))
    if not new_pw or len(new_pw) < 8:
        flash('New password must be at least 8 characters.', 'error')
        return redirect(request.referrer or url_for('admin.dashboard'))
    if new_pw != confirm:
        flash('New password and confirmation do not match.', 'error')
        return redirect(request.referrer or url_for('admin.dashboard'))

    set_admin_password(new_pw)
    record('settings', 'Changed admin password')
    flash('Admin password changed. Use the new password on next login.', 'success')
    return redirect(url_for('admin.settings'))

