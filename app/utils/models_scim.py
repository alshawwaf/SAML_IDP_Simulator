"""SCIM 2.0 data models.

Lives separately from app/utils/models.py to keep the SAML side untouched.
All tables in this module are prefixed `scim_` in the database.
"""
from datetime import datetime
import uuid

from app.utils.models import db


class ScimTarget(db.Model):
    """An outbound SCIM endpoint we push to (e.g., a Harmony SASE tenant).

    Bearer token is Fernet-encrypted at rest using SCIM_ENCRYPTION_KEY.
    """
    __tablename__ = "scim_target"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    base_url = db.Column(db.String(255), nullable=False)
    bearer_token_encrypted = db.Column(db.LargeBinary, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    last_sync_at = db.Column(db.DateTime, nullable=True)
    last_sync_status = db.Column(db.String(20), nullable=True)  # ok | partial | error
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ScimPushLog(db.Model):
    """Audit log of every outbound SCIM push. Invaluable for live demos."""
    __tablename__ = "scim_push_log"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("scim_target.id", ondelete="SET NULL"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey("scim_group.id", ondelete="SET NULL"), nullable=True)
    operation = db.Column(db.String(40), nullable=False)  # CREATE_USER, UPDATE_USER, DELETE_USER, PATCH_GROUP_MEMBERS, ...
    request_method = db.Column(db.String(10), nullable=False)
    request_url = db.Column(db.String(500), nullable=False)
    request_body = db.Column(db.Text, nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    response_body = db.Column(db.Text, nullable=True)
    error = db.Column(db.Text, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ScimInboundToken(db.Model):
    """Bearer tokens authorizing SCIM clients to push TO our /scim/v2 endpoints.

    Stored as SHA-256 hash; the raw token is shown to the admin ONCE on creation.
    """
    __tablename__ = "scim_inbound_token"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)  # sha256 hex
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)


class ScimGroup(db.Model):
    """SCIM Group resource. Distinct from the User.groups JSON list (which is for SAML claims)."""
    __tablename__ = "scim_group"

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(120), nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    display_name = db.Column(db.String(150), nullable=False, unique=True)
    external_id = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    members = db.relationship("ScimGroupMember", backref="group", cascade="all, delete-orphan")


class ScimGroupMember(db.Model):
    """Many-to-many between ScimGroup and User."""
    __tablename__ = "scim_group_member"

    id = db.Column(db.Integer, primary_key=True)
    group_pk = db.Column(db.Integer, db.ForeignKey("scim_group.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint("group_pk", "user_id", name="uq_scim_group_member"),)
