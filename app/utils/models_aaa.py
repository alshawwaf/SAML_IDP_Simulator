"""Data models for the RADIUS / TACACS+ AAA simulators.

PURE ADDITIONS — new tables only. The existing User / SAML / SCIM models are
untouched, so the SAML flow cannot regress. RADIUS and TACACS+ authenticate
against the shared `User` directory; these tables add the per-user AAA
attributes (MFA/OTP), the AAA auth log, and portal-editable connection settings.
"""
from datetime import datetime

from app.utils.models import db
from app.utils.config_manager import config_manager
from app.utils.crypto import encrypt_token, decrypt_token


class AaaUserAuth(db.Model):
    """Per-user AAA attributes. Optional — a user with no row has MFA off. The
    OTP is a static, predictable demo passcode (not a real secret), kept in the
    clear so demos are repeatable; documented as such."""
    __tablename__ = "aaa_user_auth"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"),
        unique=True, nullable=False, index=True,
    )
    mfa = db.Column(db.Boolean, nullable=False, default=False)
    otp = db.Column(db.String(32), nullable=False, default="")
    user = db.relationship(
        "User",
        backref=db.backref("aaa", uselist=False, cascade="all, delete-orphan"),
    )


class AaaLog(db.Model):
    """One row per RADIUS/TACACS+ event — never stores the password or OTP, only
    the username, source NAS, and outcome."""
    __tablename__ = "aaa_log"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    proto = db.Column(db.String(10))      # radius | tacacs
    kind = db.Column(db.String(16))       # auth | acct | author
    username = db.Column(db.String(150))
    nas = db.Column(db.String(64))
    result = db.Column(db.String(24))     # accept | reject | challenge | start | stop | error
    detail = db.Column(db.String(255))


class AaaSetting(db.Model):
    """Portal-editable connection settings (shared secrets, ports, default OTP).
    Read by both the web process and the protocol process. Secret values are
    Fernet-encrypted at rest (same crypto as SCIM tokens)."""
    __tablename__ = "aaa_setting"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")
    is_secret = db.Column(db.Boolean, nullable=False, default=False)


# setting key -> (config_manager attr used as env/default fallback, is_secret, caster)
_SETTING_SPEC = {
    "radius_secret":    ("RADIUS_SECRET",    True,  str),
    "radius_auth_port": ("RADIUS_AUTH_PORT", False, int),
    "radius_acct_port": ("RADIUS_ACCT_PORT", False, int),
    "tacacs_secret":    ("TACACS_SECRET",    True,  str),
    "tacacs_port":      ("TACACS_PORT",      False, int),
    "default_otp":      ("AAA_DEFAULT_OTP",  False, str),
}


def get_setting(key):
    """Effective value: saved-in-portal (decrypted if secret) > env > default."""
    env_attr, is_secret, cast = _SETTING_SPEC[key]
    row = AaaSetting.query.filter_by(key=key).first()
    if row is not None and row.value:
        try:
            raw = decrypt_token(row.value.encode()) if is_secret else row.value
            return cast(raw)
        except Exception:
            pass  # fall back to env/default if a stored value is unreadable
    return cast(getattr(config_manager, env_attr))


def set_setting(key, value):
    """Persist a setting. Ports are range-validated; secrets are encrypted."""
    if key not in _SETTING_SPEC:
        raise ValueError(f"Unknown setting: {key}")
    env_attr, is_secret, cast = _SETTING_SPEC[key]
    if key.endswith("_port"):
        iv = int(value)
        if not (1 <= iv <= 65535):
            raise ValueError(f"{key} must be between 1 and 65535")
        value = iv
    cast(value)  # validate castability
    stored = encrypt_token(str(value)).decode() if is_secret else str(value)
    row = AaaSetting.query.filter_by(key=key).first()
    if row is None:
        row = AaaSetting(key=key)
        db.session.add(row)
    row.value = stored
    row.is_secret = is_secret
    db.session.commit()


def settings_view():
    """All effective settings (secrets in plaintext — admin-only page)."""
    return {k: get_setting(k) for k in _SETTING_SPEC}


# --- helpers --------------------------------------------------------------
def user_aaa(user):
    return AaaUserAuth.query.filter_by(user_id=user.id).first() if user else None


def recent_aaa_logs(proto=None, limit=150):
    q = AaaLog.query.order_by(AaaLog.id.desc())
    if proto:
        q = q.filter_by(proto=proto)
    return q.limit(limit).all()


def log_event(proto, kind, username, nas, result, detail=""):
    try:
        db.session.add(AaaLog(
            proto=proto, kind=kind, username=username or "",
            nas=nas or "", result=result, detail=(detail or "")[:255],
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
