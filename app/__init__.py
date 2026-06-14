import os
import shutil
import uuid

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.exc import IntegrityError

from app.utils.models import db, User, ServiceProvider, ensure_schema
from app.utils.config_manager import config_manager
from app.utils.logger_main import logger
from app.utils.path_config import BASE_DIR
from app.utils.extensions import limiter

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
    
    # Default Service Provider templates for the five validated Check Point
    # integrations. Entity ID / ACS URL are the reference-lab values these were
    # validated against (concrete examples) — replace them with your own
    # environment's values under Admin → Service Providers. The claim mappings
    # are confirmed working against real SmartConsole, Infinity Portal, Identity
    # Awareness (Captive Portal SAML), Remote Access VPN, and Identity & Trust —
    # plus a built-in loopback test SP (/saml-test).
    default_sps = [
        {
            # Built-in loopback test SP — works on any deploy with no external
            # Service Provider. Visit /saml-test to run SSO and view the decoded,
            # signed assertion. The ACS is relative so it resolves to this host.
            "name": "Built-in SAML Test",
            "entity_id": "urn:cp-idp-simulator:saml-test",
            "acs_url": "/saml-test/acs",
            "attr_map": [
                {"claim": "email", "value": "email"},
                {"claim": "firstName", "value": "first_name"},
                {"claim": "lastName", "value": "last_name"},
                # Demonstrate BOTH group claim styles: readable names + Entra-style UUIDs.
                {"claim": "groups", "value": "group_names"},
                {"claim": "groupIds", "value": "group_ids"},
                {"claim": "userId", "value": "user_id"},
            ],
        },
        {
            # Check Point SmartConsole admin SAML (R81.20+). The IdP signs the
            # SAML Response (not just the assertion) — see app/utils/saml.py.
            "name": "SmartConsole",
            "entity_id": "https://mgmt-sp-ab5d99e9-f537-4a34-aba3-e1dd12d6104b.local/cpmws/saml/acs/id/ab5d99e9-f537-4a34-aba3-e1dd12d6104b",
            "acs_url": "https://10.1.1.100/cpmws/saml/acs/sso",
            "attr_map": [
                {"claim": "username", "value": "username"},
                # Group claim carries readable display names so SmartConsole access
                # roles can match on group (switch to group_ids for Entra-style UUIDs).
                {"claim": "groups", "value": "group_names"},
            ],
        },
        {
            # Check Point Infinity Portal (Generic SAML Server). The userId
            # claim must be non-empty, so map it to the stable user_id UUID.
            # ACS host is the regional portal endpoint (us / eu / au / in).
            "name": "InfinityPortal",
            "entity_id": "263cdbe8-0077-4536-abc8-05b92c74679d.cloudinfra.checkpoint.com",
            "acs_url": "https://cloudinfra-gw-us.portal.checkpoint.com/api/saml/sso",
            "attr_map": [
                {"claim": "identity/claims/givenname", "value": "first_name"},
                {"claim": "identity/claims/name", "value": "last_name"},
                {"claim": "identity/claims/emailaddress", "value": "email"},
                {"claim": "groups", "value": "group_names"},
                {"claim": "urn:mace:dir:attribute-def:userId", "value": "user_id"},
            ],
        },
        {
            # Check Point Identity Awareness — Captive Portal SAML login. The
            # gateway's SP ID appears in both the Entity ID and the ACS path.
            # NameID carries the email; a single "username" claim (= email) is
            # all the captive portal needs.
            "name": "IDA-CaptivePortalSAML",
            "entity_id": "https://10.1.1.111/connect/spPortal/ACS/ID/34b5af6d-4db7-43a6-a1cb-5298e884d0b3",
            "acs_url": "https://10.1.1.111/connect/spPortal/ACS/Login/34b5af6d-4db7-43a6-a1cb-5298e884d0b3",
            "attr_map": [
                {"claim": "username", "value": "email"},
            ],
        },
        {
            # Check Point Remote Access VPN — SAML auth via the gateway's
            # saml-vpn portal. Same "SP ID in both paths" shape as IDA, but
            # under /saml-vpn/. NameID=email; username->email plus a
            # "group attr" claim -> groups.
            "name": "RemoteAccessVPN",
            "entity_id": "https://10.1.1.111/saml-vpn/spPortal/ACS/ID/acb09bcb-f847-448e-a38b-a92e466f9db4",
            "acs_url": "https://10.1.1.111/saml-vpn/spPortal/ACS/Login/acb09bcb-f847-448e-a38b-a92e466f9db4",
            "attr_map": [
                {"claim": "username", "value": "email"},
                {"claim": "group attr", "value": "group_names"},
            ],
        },
        {
            # Check Point Infinity Identity & Trust — Generic SAML Server, the
            # same shape as Infinity Portal but a distinct tenant. The userId
            # claim maps to the stable user_id UUID.
            "name": "IdentityAndTrust",
            "entity_id": "68719a1b-574e-4845-b7f9-724b28fd33f4.cloudinfra.checkpoint.com",
            "acs_url": "https://cloudinfra-gw-us.portal.checkpoint.com/api/saml/sso",
            "attr_map": [
                {"claim": "identity/claims/givenname", "value": "first_name"},
                {"claim": "identity/claims/name", "value": "last_name"},
                {"claim": "identity/claims/emailaddress", "value": "email"},
                {"claim": "groups", "value": "group_names"},
                {"claim": "urn:mace:dir:attribute-def:userId", "value": "user_id"},
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
        try:
            db.session.commit()
            logger.info(f"Created {len(default_users)} default users")
        except IntegrityError:
            db.session.rollback()  # another worker seeded first — safe to ignore
            logger.info("Default users already present; skipping seed.")
    
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
        try:
            db.session.commit()
            logger.info(f"Created {len(default_sps)} default service providers")
        except IntegrityError:
            db.session.rollback()  # another worker seeded first — safe to ignore
            logger.info("Default service providers already present; skipping seed.")


def ensure_builtin_test_sp():
    """Make sure the built-in loopback test SP exists — even on databases that
    were seeded before it was added — so /saml-test always works. Idempotent."""
    TEST_ENTITY = "urn:cp-idp-simulator:saml-test"
    if ServiceProvider.query.filter_by(entity_id=TEST_ENTITY).first():
        return
    db.session.add(ServiceProvider(
        name="Built-in SAML Test",
        entity_id=TEST_ENTITY,
        acs_url="/saml-test/acs",
        attr_map=[
            {"claim": "email", "value": "email"},
            {"claim": "firstName", "value": "first_name"},
            {"claim": "lastName", "value": "last_name"},
            {"claim": "groups", "value": "group_names"},
            {"claim": "groupIds", "value": "group_ids"},
            {"claim": "userId", "value": "user_id"},
        ],
    ))
    try:
        db.session.commit()
        logger.info("Seeded built-in SAML test SP")
    except IntegrityError:
        db.session.rollback()


def migrate_legacy_groups_to_entities():
    """One-time, idempotent migration from the legacy free-text User.groups list
    to first-class Group entities.

    Two steps:
      1. Materialize: for every label in each user's (now dormant) `groups` list,
         upsert a ScimGroup by display_name and ensure a ScimGroupMember link.
         Existing group assignments survive as real groups with stable UUIDs.
      2. Repoint: rewrite every Service Provider attribute-map entry whose source
         is the dormant `groups` column to the membership-derived `group_names`,
         so the same SAML claim now carries real group names.

    Guarded by a marker file on the data volume so it runs exactly once. After it
    runs, real groups are authoritative and the dormant column is ignored forever
    — re-running would resurrect memberships an admin later removed. Runs inside
    the _init_database() file lock, so it's safe across gunicorn workers. Failures
    are logged and leave the marker absent so the next boot retries; they never
    crash startup (the SAML flow must come up regardless).
    """
    from app.utils.models_scim import ScimGroup, ScimGroupMember

    marker = PERSIST_DIR / ".groups-migrated"
    if marker.exists():
        return

    try:
        # 1. Labels -> ScimGroup + membership.
        groups_by_name = {g.display_name: g for g in ScimGroup.query.all()}
        created_groups = created_members = 0
        for user in User.query.all():
            for raw in (user.groups or []):
                label = (raw or "").strip()
                if not label:
                    continue
                group = groups_by_name.get(label)
                if group is None:
                    group = ScimGroup(display_name=label)
                    db.session.add(group)
                    db.session.flush()  # populate group.id
                    groups_by_name[label] = group
                    created_groups += 1
                if ScimGroupMember.query.filter_by(group_pk=group.id, user_id=user.id).first() is None:
                    db.session.add(ScimGroupMember(group_pk=group.id, user_id=user.id))
                    created_members += 1

        # 2. Repoint SP attribute maps: "groups" -> "group_names".
        repointed = 0
        for sp in ServiceProvider.query.all():
            if not sp.attr_map:
                continue
            new_map, changed = [], False
            for m in sp.attr_map:
                if isinstance(m, dict) and m.get("value") == "groups":
                    m = {**m, "value": "group_names"}
                    changed = True
                new_map.append(m)
            if changed:
                sp.attr_map = new_map
                repointed += 1

        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Legacy-groups migration failed; will retry on next boot.")
        return

    try:
        marker.write_text("Legacy User.groups materialized into ScimGroup entities.\n")
    except OSError as e:
        logger.warning("Could not write groups-migration marker %s: %s", marker, e)

    if created_groups or created_members or repointed:
        logger.info(
            "Legacy-groups migration: materialized %d group(s), %d membership(s); "
            "repointed %d Service Provider attribute map(s) to group_names.",
            created_groups, created_members, repointed,
        )


def _log_admin_credentials():
    """One-line startup hint about which admin password is active."""
    if config_manager.ADMIN_PASSWORD_HASH_FILE.exists():
        source = "custom (set via Settings → Change Admin Password)"
    elif config_manager.ADMIN_PASSWORD_IS_DEFAULT:
        source = "default 'CpDemo2026' — change it in Settings after first login"
    else:
        source = "from ADMIN_PASSWORD env var"
    logger.info("ADMIN portal: username=%s, password=%s", config_manager.ADMIN_USERNAME, source)


def _init_database():
    """Create tables, run additive migrations, and seed defaults — serialized
    across processes with an exclusive file lock so concurrent gunicorn workers
    can't race on a fresh database (duplicate CREATE TABLE / UNIQUE-constraint
    seed inserts). On platforms without fcntl (e.g. Windows dev) the lock is a
    no-op, which is fine because those run single-process.
    """
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    lock_file = open(PERSIST_DIR / ".init.lock", "w")
    try:
        try:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass  # no fcntl available — single-process dev, nothing to serialize
        db.create_all()
        ensure_schema(db.engine)
        seed_default_data()
        ensure_builtin_test_sp()
        migrate_legacy_groups_to_entities()
        if config_manager.scim_enabled():
            from app.routes.scim.bootstrap import seed_default_scim_data
            seed_default_scim_data()
    finally:
        lock_file.close()  # closing the fd releases the flock


def create_app(init_db=True):
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
    limiter.init_app(app)

    # Make the runtime SCIM flag visible to every template — drives nav-link
    # visibility and the dashboard toggle.
    @app.context_processor
    def inject_scim_flag():
        return {"scim_enabled": config_manager.scim_enabled()}

    # Admin identity + password state for the navbar account menu (rendered on
    # every page; both lookups are cheap — an attribute read and a file check).
    @app.context_processor
    def inject_admin_account():
        from app.utils.admin_password import admin_password_overridden
        return {
            "admin_username": config_manager.ADMIN_USERNAME,
            "admin_password_overridden": admin_password_overridden(),
        }

    with app.app_context():
        from app.routes.metadata import metadata_bp
        from app.routes.auth import auth_bp
        from app.routes.admin import admin_bp
        from app.routes.radius import radius_bp
        from app.routes.tacacs import tacacs_bp

        app.register_blueprint(metadata_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(admin_bp)
        app.register_blueprint(radius_bp)
        app.register_blueprint(tacacs_bp)

        # SP-initiated SSO may arrive via the HTTP-POST binding (AuthnRequest in
        # a form with no Flask CSRF token). Exempt just the /sso view; /login
        # keeps CSRF protection (it's a browser form that includes the token).
        csrf.exempt(app.view_functions['auth.sso'])
        csrf.exempt(app.view_functions['auth.saml_test_acs'])

        # SCIM models are always imported so their tables exist; the SCIM
        # feature itself is gated at runtime by config_manager.scim_enabled().
        from app.utils import models_scim  # noqa: F401
        from app.utils import models_aaa   # noqa: F401  (RADIUS/TACACS tables)

        # The protocol process (app.services.runner) calls create_app(init_db=
        # False): only the web process runs migrations/seeding, so there's no
        # init race; the protocol side just reads the schema the web created.
        if init_db:
            _init_database()
            _log_admin_credentials()

        # SCIM routes are always registered; scim_enabled() (runtime, default on)
        # gates them so the admin can toggle SCIM from the portal without a restart.
        from app.routes.scim import register_scim_blueprints
        register_scim_blueprints(app, csrf)
        if config_manager.SCIM_ENCRYPTION_KEY_DERIVED:
            logger.info("SCIM encryption key auto-derived from SECRET_KEY (override with SCIM_ENCRYPTION_KEY env var)")
        logger.info(
            "SCIM registered at %s; currently %s (toggle in the admin dashboard).",
            config_manager.SCIM_BASE_PATH,
            "ENABLED" if config_manager.scim_enabled() else "disabled",
        )

        logger.info("Application initialized and database created.")

    return app
