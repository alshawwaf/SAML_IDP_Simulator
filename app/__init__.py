import os
import shutil
import uuid

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from app.utils.models import db, User, ServiceProvider, ensure_schema
from app.utils.config_manager import config_manager
from app.utils.logger_main import logger
from app.utils.path_config import BASE_DIR

csrf = CSRFProtect()


# Persistent DB location. /app/data is mounted to a Docker volume in
# docker-compose.yml (saml_idp_data), so the SQLite file survives container
# rebuilds. The legacy location was /app/app.db (NOT on the volume) — every
# Dokploy redeploy wiped it. _migrate_legacy_db() handles the one-time move.
PERSIST_DIR = BASE_DIR / "data"
DB_FILE = PERSIST_DIR / "app.db"
LEGACY_DB_FILE = BASE_DIR / "app.db"


def _migrate_legacy_db():
    """If a legacy /app/app.db exists and the new /app/data/app.db does not,
    copy it over so the operator keeps existing users/SPs/SCIM targets through
    the relocation. Idempotent — does nothing once /app/data/app.db exists.
    """
    try:
        PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Could not create persist dir %s: %s", PERSIST_DIR, e)
        return

    if DB_FILE.exists():
        return  # already migrated (or fresh install on the new layout)

    if LEGACY_DB_FILE.exists() and LEGACY_DB_FILE.stat().st_size > 0:
        try:
            shutil.copy2(LEGACY_DB_FILE, DB_FILE)
            logger.info(
                "Migrated legacy DB from %s to %s (size %d bytes). "
                "The legacy file is kept as a one-time backup; remove it "
                "once you've confirmed the new DB works.",
                LEGACY_DB_FILE, DB_FILE, LEGACY_DB_FILE.stat().st_size,
            )
        except OSError as e:
            logger.error("Failed to migrate legacy DB: %s", e)

def seed_default_data():
    """Create default users and service providers if database is empty
    
    NOTE: These are DEMO credentials for Check Point testing purposes.
    Users: demo.user, john.smith, jane.doe (password: Cpwins!1@2026)
    """
    
    # Default SAML Users for Check Point demos
    default_users = [
        {
            "username": "demo.user",
            "email": "demo.user@cpdemo.ca",
            "password": "Cpwins!1@2026",
            "first_name": "Demo",
            "last_name": "User",
            "groups": ["saml_users", "vpn_users"],
        },
        {
            "username": "john.smith",
            "email": "john.smith@cpdemo.ca",
            "password": "Cpwins!1@2026",
            "first_name": "John",
            "last_name": "Smith",
            "groups": ["saml_users", "admins"],
        },
        {
            "username": "jane.doe",
            "email": "jane.doe@cpdemo.ca",
            "password": "Cpwins!1@2026",
            "first_name": "Jane",
            "last_name": "Doe",
            "groups": ["saml_users", "security_admins"],
        },
    ]
    
    # Default Service Providers for Check Point products
    default_sps = [
        {
            "name": "Harmony Connect Portal",
            "entity_id": "https://10.1.1.111/connect/spPortal/ACS/ID/4bd3c39d-3f85-444f-9230-92c922b93db4",
            "acs_url": "https://10.1.1.111/connect/spPortal/ACS/Login/4bd3c39d-3f85-444f-9230-92c922b93db4",
            "attr_map": [
                {"claim": "email", "value": "email"},
                {"claim": "firstName", "value": "first_name"},
                {"claim": "lastName", "value": "last_name"},
                {"claim": "groups", "value": "groups"},
            ],
        },
        {
            "name": "Quantum Security Gateway",
            "entity_id": "https://gateway.cpdemo.local/saml/sp",
            "acs_url": "https://gateway.cpdemo.local/saml/acs",
            "attr_map": [
                {"claim": "email", "value": "email"},
                {"claim": "uid", "value": "username"},
                {"claim": "groups", "value": "groups"},
            ],
        },
        {
            "name": "SmartConsole",
            "entity_id": "https://smartconsole.cpdemo.local/saml/metadata",
            "acs_url": "https://smartconsole.cpdemo.local/saml/acs",
            "attr_map": [
                {"claim": "email", "value": "email"},
                {"claim": "name", "value": "first_name"},
                {"claim": "surname", "value": "last_name"},
                {"claim": "role", "value": "groups"},
            ],
        },
    ]
    
    # Create default users if none exist
    if User.query.count() == 0:
        logger.info("Creating default demo users...")
        for user_data in default_users:
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                first_name=user_data["first_name"],
                last_name=user_data["last_name"],
                groups=user_data["groups"],
                user_id=str(uuid.uuid4()),
            )
            user.set_password(user_data["password"])
            db.session.add(user)
        db.session.commit()
        logger.info(f"Created {len(default_users)} default users")
    
    # Create default service providers if none exist
    if ServiceProvider.query.count() == 0:
        logger.info("Creating default service providers...")
        for sp_data in default_sps:
            sp = ServiceProvider(
                name=sp_data["name"],
                entity_id=sp_data["entity_id"],
                acs_url=sp_data["acs_url"],
                attr_map=sp_data["attr_map"],
            )
            db.session.add(sp)
        db.session.commit()
        logger.info(f"Created {len(default_sps)} default service providers")


def _log_admin_credentials():
    """One-line startup hint about which admin password is active."""
    if config_manager.ADMIN_PASSWORD_HASH_FILE.exists():
        source = "custom (set via Settings → Change Admin Password)"
    elif config_manager.ADMIN_PASSWORD_IS_DEFAULT:
        source = "default 'CpDemo2026' — change it in Settings after first login"
    else:
        source = "from ADMIN_PASSWORD env var"
    logger.info("ADMIN portal: username=%s, password=%s", config_manager.ADMIN_USERNAME, source)


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config_manager.SECRET_KEY

    # Behind Dokploy/Traefik (or any reverse proxy) the app sees the internal
    # http://0.0.0.0:5000 host. Honor X-Forwarded-Proto/Host/Port so
    # request.url_root reflects the real external URL (https://idp.example.com).
    # This is what lets the metadata/SSO URLs auto-derive correctly without
    # any env vars. Safe no-op when there's no proxy.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Migrate any pre-volume DB into the persisted volume BEFORE SQLAlchemy
    # opens the file, then point at the new location.
    _migrate_legacy_db()
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_FILE}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    logger.info("Database file: %s", DB_FILE)

    db.init_app(app)
    csrf.init_app(app)

    # Make ENABLE_SCIM visible to every template — drives nav-link visibility.
    @app.context_processor
    def inject_scim_flag():
        return {"scim_enabled": config_manager.ENABLE_SCIM}

    with app.app_context():
        from app.routes.metadata import metadata_bp
        from app.routes.auth import auth_bp
        from app.routes.admin import admin_bp

        app.register_blueprint(metadata_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(admin_bp)

        # Import SCIM models before create_all() so their tables get created
        # in the same pass. The import is no-op-cheap when SCIM is off — it
        # just defines SQLAlchemy classes; no routes or workers start.
        if config_manager.ENABLE_SCIM:
            from app.utils import models_scim  # noqa: F401

        db.create_all()
        ensure_schema(db.engine)
        seed_default_data()
        _log_admin_credentials()

        if config_manager.ENABLE_SCIM:
            from app.routes.scim import register_scim_blueprints
            from app.routes.scim.bootstrap import seed_default_scim_data
            register_scim_blueprints(app, csrf)
            seed_default_scim_data()
            if config_manager.SCIM_ENCRYPTION_KEY_DERIVED:
                logger.info("SCIM encryption key auto-derived from SECRET_KEY (override with SCIM_ENCRYPTION_KEY env var)")
            logger.info(
                "SCIM endpoints enabled at %s (server) and /admin/scim (admin UI)",
                config_manager.SCIM_BASE_PATH,
            )
        else:
            logger.info("SCIM disabled (set ENABLE_SCIM=true to enable).")

        logger.info("Application initialized and database created.")

    return app
