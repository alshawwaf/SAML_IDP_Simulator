from flask import Flask
from .utils.models import db
from .utils.saml import IdPHandler
from .utils.path_config import paths
from .utils.config_manager import IdPConfigManager
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import os
from werkzeug.middleware.proxy_fix import ProxyFix
from pathlib import Path


def create_app():
    app = Flask(__name__, static_folder="static")

    load_dotenv()

    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-key-123"),
        SQLALCHEMY_DATABASE_URI="sqlite:///" + str(paths.base_dir / "users.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SAML_ENDPOINT=os.getenv("SSO_SERVICE_URL", "https://10.1.1.200:5000/sso"),
        ADMIN_USERNAME=os.getenv("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD_HASH=generate_password_hash(
            os.getenv("ADMIN_PASSWORD", "Vpn123!1")
        ),
    )

    # Initialize extensions AFTER config
    db.init_app(app)
    csrf = CSRFProtect(app)

    # Create tables
    with app.app_context():
        db.create_all()

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.metadata import metadata_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/")
    app.register_blueprint(metadata_bp)
    app.register_blueprint(admin_bp)

    # Configure CSP to allow css to load inside the admin pages
    csp = {
        "default-src": "'self'",
        "style-src": [
            "'self'",
            "https://cdn.jsdelivr.net",
            "'unsafe-inline'",
        ],
        "script-src": [
            "'self'",
            "https://cdn.jsdelivr.net",
            "'unsafe-inline'",
        ],
        "font-src": ["'self'", "https://cdn.jsdelivr.net", "data:"],
        "img-src": [
            "'self'",
            "data:",
            "https://via.placeholder.com",  # If using placeholder images
        ],
    }

    Talisman(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=[],
    )

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    @app.template_filter("zip")
    def zip_filter(a, b):
        return zip(a, b)

    return app
