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

    @staticmethod
    def get_editable_user_fields():
        # Source fields offered in the SAML claim-mapping dropdowns
        # (sp_new/sp_edit/sp_modals iterate this list). `user_id` — the stable
        # per-user UUID — is included as a read-only claim source so an IdP
        # "userId"/"objectId" claim can map to an immutable identifier, mirroring
        # Entra objectId / Okta id. It is NOT user-editable (the add/edit-user
        # forms use a fixed field set, not this list). `active` stays excluded
        # (it's writable via SCIM, not a useful SAML claim).
        exclude = {"id", "password_hash", "created_at", "updated_at", "active"}
        fields = [c.name for c in User.__table__.columns if c.name not in exclude]
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
