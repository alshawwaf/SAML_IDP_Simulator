from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False, default='')
    last_name = db.Column(db.String(80), nullable=False, default='')
    user_id = db.Column(db.String(120), nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    # DORMANT: the legacy free-text group list. Groups are now first-class
    # entities (app.utils.models_scim.ScimGroup) and a user's groups come from
    # membership, surfaced via the group_names/group_ids properties below. This
    # column is no longer read or written by the app — kept (not dropped) to
    # avoid a destructive SQLite migration; a one-time startup migration copied
    # its values into real groups. Safe to drop later via Flask-Migrate.
    groups = db.Column(db.JSON, default=lambda: ["saml_users"])
    is_admin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    # SCIM external_id — set by upstream provisioners (Entra `objectId`, Okta user.id, etc.)
    # to correlate with their own user records. Indexed for filter lookups.
    external_id = db.Column(db.String(255), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def group_names(self):
        """Display names of the groups this user belongs to — the readable,
        Okta-style SAML group claim source. Derived from group membership
        (ScimGroupMember), not a column. Consumed by auth.py via getattr()."""
        return [m.group.display_name for m in self.scim_memberships]

    @property
    def group_ids(self):
        """Stable UUIDs of the groups this user belongs to — the Entra
        objectId-style SAML group claim source. Derived from group membership
        (ScimGroupMember), not a column. Consumed by auth.py via getattr()."""
        return [m.group.group_id for m in self.scim_memberships]

    @staticmethod
    def get_editable_user_fields():
        # Source fields offered in the SAML claim-mapping dropdowns
        # (sp_new/sp_edit/sp_modals iterate this list). `user_id` — the stable
        # per-user UUID — is included as a read-only claim source so an IdP
        # "userId"/"objectId" claim can map to an immutable identifier, mirroring
        # Entra objectId / Okta id. It is NOT user-editable (the add/edit-user
        # forms use a fixed field set, not this list). `active` stays excluded
        # (it's writable via SCIM, not a useful SAML claim). The legacy `groups`
        # column is excluded (dormant) — group claims now come from the
        # membership-derived group_names/group_ids properties below.
        exclude = {"id", "password_hash", "created_at", "updated_at", "active", "groups"}
        fields = [c.name for c in User.__table__.columns if c.name not in exclude]
        # Group claim sources derived from first-class Group membership (not
        # columns): group_names = member group display names (Okta-style);
        # group_ids = member group UUIDs (Entra objectId-style). Pick either per SP.
        fields.extend(["group_names", "group_ids"])
        fields.append("password")
        return fields

    
class ServiceProvider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entity_id = db.Column(db.String(255), unique=True, nullable=False)
    acs_url = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    attr_map = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ActivityLog(db.Model):
    """App-wide audit log — one row per notable change (auth, user/SP CRUD,
    SCIM config, settings). Written via app.utils.activity.record()."""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    actor = db.Column(db.String(150))                     # admin username / user / "system"
    category = db.Column(db.String(40), index=True)       # auth|user|service_provider|scim|saml|settings
    action = db.Column(db.String(160))                    # human-readable summary
    target = db.Column(db.String(255))                    # affected object (username, SP name, …)
    status = db.Column(db.String(20), default="success")  # success | error | info
    detail = db.Column(db.Text)                           # optional JSON/text context
    ip = db.Column(db.String(64))
    method = db.Column(db.String(10))
    path = db.Column(db.String(255))


def ensure_schema(engine):
    """Idempotent additive migrations. Safe to call on every startup.

    SQLite's ALTER TABLE supports ADD COLUMN, so we don't need alembic for the
    handful of additive changes we need. If/when destructive migrations become
    necessary, swap this for Flask-Migrate.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if not inspector.has_table("user"):
        # First boot — create_all() handles it, no migration needed.
        return

    existing_cols = {c["name"] for c in inspector.get_columns("user")}
    if "active" not in existing_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE user ADD COLUMN active BOOLEAN NOT NULL DEFAULT 1"))
    if "external_id" not in existing_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE user ADD COLUMN external_id VARCHAR(255)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_user_external_id ON user (external_id)"))

    # scim_group.description — added when Groups became first-class admin-managed
    # entities. create_all() makes it on fresh DBs; this covers DBs that already
    # had scim_group (e.g. SCIM was used before this feature).
    if inspector.has_table("scim_group"):
        scim_group_cols = {c["name"] for c in inspector.get_columns("scim_group")}
        if "description" not in scim_group_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scim_group ADD COLUMN description VARCHAR(255)"))
