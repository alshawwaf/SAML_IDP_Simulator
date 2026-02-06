from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app.utils.models import db, User, ServiceProvider
from app.utils.config_manager import config_manager
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

@admin_bp.route('/')
@admin_required
def dashboard():
    users = User.query.all()
    sps = ServiceProvider.query.all()
    user_fields = User.get_editable_user_fields()
    return render_template('admin/users.html', users=users, sps=sps, user_fields=user_fields)

@admin_bp.route('/settings')
@admin_required
def settings():
    return render_template('admin/settings.html', config=config_manager.get_all_config())

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
    return render_template('admin/user_management.html', users=users, user_fields=user_fields)

@admin_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    first_name = request.form.get('first_name', '')
    last_name = request.form.get('last_name', '')
    groups_str = request.form.get('groups', '')
    
    # Parse groups from comma-separated string
    groups = [g.strip() for g in groups_str.split(',') if g.strip()] if groups_str else ['saml_users']
    
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
        groups=groups
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
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
        groups_str = request.form.get('groups', '')
        if groups_str:
            user.groups = [g.strip() for g in groups_str.split(',') if g.strip()]
        if request.form.get('password'):
            user.set_password(request.form.get('password'))
        db.session.commit()
        flash('User updated', 'success')
        return redirect(url_for('admin.user_management'))
    return render_template('admin/edit_user.html', user=user, user_fields=user_fields)

@admin_bp.route('/users/<username>/delete')
@admin_required
def delete_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    db.session.delete(user)
    db.session.commit()
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
        'groups': ','.join(user.groups) if user.groups else '',
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
    groups_str = request.form.get('groups', '')
    if groups_str:
        user.groups = [g.strip() for g in groups_str.split(',') if g.strip()]
    
    db.session.commit()
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
    flash(f'Password reset successfully for {username}', 'success')
    return redirect(url_for('admin.user_management'))

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
            attr_map.append({'claim': claim_name, 'field': claim_value})
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
            attr_map.append({'claim': claim_name, 'field': claim_value})
        i += 1
    sp.attr_map = attr_map
    
    db.session.commit()
    flash('Service Provider updated successfully', 'success')
    return redirect(url_for('admin.list_sps'))

@admin_bp.route('/service-providers/<int:sp_id>/delete')
@admin_required
def delete_sp(sp_id):
    sp = ServiceProvider.query.get_or_404(sp_id)
    db.session.delete(sp)
    db.session.commit()
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
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == config_manager.ADMIN_USERNAME and password == config_manager.ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin.dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('admin/login.html')

@admin_bp.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin.login'))

