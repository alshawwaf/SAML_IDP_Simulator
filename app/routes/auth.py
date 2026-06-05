from flask import Blueprint, request, render_template, session

from app.utils.saml import IdPHandler
from app.utils.user_manager import UserManager
from app.utils.models import ServiceProvider
from app.utils.extensions import limiter

auth_bp = Blueprint('auth', __name__)
saml_handler = IdPHandler()


@auth_bp.route('/sso', methods=['GET', 'POST'])
def sso():
    """SP-initiated SSO entry point. Accepts the AuthnRequest over either
    binding (Redirect=GET, POST=form), resolves the requesting SP, stashes the
    SAML context in the session, and shows the login form."""
    saml_request = request.args.get('SAMLRequest') or request.form.get('SAMLRequest')
    relay_state = request.args.get('RelayState') or request.form.get('RelayState')
    if not saml_request:
        return "No SAMLRequest found", 400

    try:
        parsed = saml_handler.parse_request(saml_request)
    except Exception:
        # Malformed/unsupported request — fall back to a contextless login so a
        # human can still demo, but without an SP we can't build a response.
        parsed = {"request_id": None, "issuer": None, "acs_url": None}

    sp = None
    if parsed.get("issuer"):
        sp = ServiceProvider.query.filter_by(entity_id=parsed["issuer"]).first()

    # The SP's configured ACS is authoritative; fall back to the request's ACS.
    acs_url = sp.acs_url if sp else parsed.get("acs_url")

    session['saml_ctx'] = {
        "request_id": parsed.get("request_id"),
        "sp_entity_id": (sp.entity_id if sp else parsed.get("issuer")),
        "acs_url": acs_url,
        "relay_state": relay_state,
        "sp_id": sp.id if sp else None,
    }
    return render_template('auth/login.html', sp_name=(sp.name if sp else None))


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("30 per minute")
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = UserManager.get_user_by_username(username)
    if not (user and UserManager.verify_password(user, password)):
        return "Invalid credentials", 401

    session['user_id'] = user.id

    ctx = session.get('saml_ctx')
    if not ctx or not ctx.get('acs_url'):
        return ("No active SAML request. Start single sign-on from your "
                "Service Provider.", 400)

    # Build the per-SP claim set from the configured attribute mapping.
    attributes = {}
    sp = ServiceProvider.query.get(ctx["sp_id"]) if ctx.get("sp_id") else None
    if sp and sp.attr_map:
        for mapping in sp.attr_map:
            claim = mapping.get("claim")
            field = mapping.get("value")
            if not claim or not field:
                continue
            val = getattr(user, field, None)
            if val is None:
                continue
            attributes[claim] = val if isinstance(val, list) else [val]

    user_info = {"email": user.email, "attributes": attributes}
    sp_info = {"entity_id": ctx.get("sp_entity_id") or "", "acs_url": ctx["acs_url"]}

    saml_response = saml_handler.build_response(
        user_info, sp_info, request_id=ctx.get("request_id"),
    )
    relay_state = ctx.get("relay_state")
    session.pop('saml_ctx', None)

    return render_template(
        'auth/saml_post.html',
        saml_response=saml_response,
        acs_url=ctx["acs_url"],
        relay_state=relay_state,
    )
