"""SCIM 2.0 blueprint package.

Registered in app/__init__.py only when config_manager.ENABLE_SCIM is true.

Phase 0: empty blueprint with a health endpoint to confirm wiring.
Phase 1+: SCIM server endpoints (/scim/v2/Users, /Groups, etc.).
Phase 3+: SCIM client + admin UI.
"""
from flask import Blueprint

from app.utils.config_manager import config_manager


scim_bp = Blueprint("scim", __name__, url_prefix=config_manager.SCIM_BASE_PATH)


def register_scim_blueprints(app, csrf=None):
    """Register all SCIM-related blueprints.

    Called once from app/__init__.py when ENABLE_SCIM is true.
    Importing the submodules here defers their loading so the
    SAML-only code path never touches SCIM code.

    Args:
        app: the Flask app
        csrf: the CSRFProtect instance — SCIM server endpoints are exempted
              since they authenticate with bearer tokens, not cookies (RFC 7644 §2).
              The /admin/scim/* admin UI is NOT exempted and uses the normal
              admin session + CSRF flow.
    """
    # Import submodules so their @scim_bp.route decorators register.
    from app.routes.scim import server  # noqa: F401
    from app.routes.scim import client  # noqa: F401
    from app.routes.scim import admin as scim_admin
    from app.routes.scim import sync as scim_sync

    app.register_blueprint(scim_bp)
    app.register_blueprint(scim_admin.scim_admin_bp)

    if csrf is not None:
        csrf.exempt(scim_bp)

    # Wire SQLAlchemy events + after_request hook for SCIM_PUSH_ON_USER_CHANGE.
    scim_sync.init_auto_sync(app)
