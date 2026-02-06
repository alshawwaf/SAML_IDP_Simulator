from flask import Blueprint, request, render_template, redirect, url_for, session
from app.utils.saml import IdPHandler
from app.utils.user_manager import UserManager

auth_bp = Blueprint('auth', __name__)
saml_handler = IdPHandler()

@auth_bp.route('/sso', methods=['GET', 'POST'])
def sso():
    saml_request = request.args.get('SAMLRequest') or request.form.get('SAMLRequest')
    if not saml_request:
        return "No SAMLRequest found", 400
    
    # In a real app, we'd decode and validate the request here
    return render_template('auth/login.html')

@auth_bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = UserManager.get_user_by_username(username)
    if user and UserManager.verify_password(user, password):
        session['user_id'] = user.id
        # Build SAML Response...
        return render_template('auth/saml_post.html', saml_response="...", acs_url="...")
    
    return "Invalid credentials", 401
