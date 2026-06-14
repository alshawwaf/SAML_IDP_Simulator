"""Data models + helpers for the RADIUS / TACACS+ AAA simulators.

PURE ADDITIONS — new tables only. The existing User / SAML / SCIM models are
untouched. RADIUS and TACACS+ authenticate against the shared `User` directory;
these tables add per-user MFA (TOTP), the AAA auth log, and portal-editable
connection settings. Shared secrets and TOTP secrets are encrypted at rest.
"""
import io
import time
from datetime import datetime

import pyotp
import qrcode
import qrcode.image.svg

from app.utils.models import db
from app.utils.config_manager import config_manager
from app.utils.crypto import encrypt_token, decrypt_token

TOTP_ISSUER = "CP Identity & Access Sim"


class AaaUserAuth(db.Model):
    """Per-user AAA attributes. Optional — a user with no row has MFA off.
    When MFA is on, `totp_secret` holds a Fernet-encrypted base32 TOTP secret."""
    __tablename__ = "aaa_user_auth"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"),
        unique=True, nullable=False, index=True,
    )
    mfa = db.Column(db.Boolean, nullable=False, default=False)
    otp = db.Column(db.String(32), nullable=False, default="")   # dormant: legacy static OTP
    totp_secret = db.Column(db.Text, nullable=True)              # encrypted base32 TOTP secret
    user = db.relationship(
        "User",
        backref=db.backref("aaa", uselist=False, cascade="all, delete-orphan"),
    )


class AaaLog(db.Model):
    """One row per RADIUS/TACACS+ event — never stores the password or codes,
    only the username, source NAS, and outcome."""
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
    """Portal-editable connection settings (shared secrets, ports). Read by both
    the web and protocol processes. Secret values are Fernet-encrypted at rest."""
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
            pass
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
    cast(value)
    stored = encrypt_token(str(value)).decode() if is_secret else str(value)
    row = AaaSetting.query.filter_by(key=key).first()
    if row is None:
        row = AaaSetting(key=key)
        db.session.add(row)
    row.value = stored
    row.is_secret = is_secret
    db.session.commit()


def settings_view():
    return {k: get_setting(k) for k in _SETTING_SPEC}


# --- TOTP (RFC 6238) MFA --------------------------------------------------
def get_totp_secret(user_auth):
    if user_auth and user_auth.totp_secret:
        try:
            return decrypt_token(user_auth.totp_secret.encode())
        except Exception:
            return None
    return None


def ensure_totp_secret(user_auth):
    """Return the user's TOTP secret, generating + storing one (encrypted) if absent."""
    existing = get_totp_secret(user_auth)
    if existing:
        return existing
    secret = pyotp.random_base32()
    user_auth.totp_secret = encrypt_token(secret).decode()
    db.session.commit()
    return secret


def regenerate_totp(user_auth):
    secret = pyotp.random_base32()
    user_auth.totp_secret = encrypt_token(secret).decode()
    db.session.commit()
    return secret


def verify_totp(user_auth, code):
    secret = get_totp_secret(user_auth)
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


def totp_info(user, user_auth):
    """Enrollment + live-code details for the admin UI, or None if no secret."""
    secret = get_totp_secret(user_auth)
    if not secret:
        return None
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=(user.email or user.username), issuer_name=TOTP_ISSUER)
    buf = io.BytesIO()
    qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage).save(buf)
    return {
        "secret": secret,
        "uri": uri,
        "qr": buf.getvalue().decode(),
        "code": totp.now(),
        "remaining": totp.interval - int(time.time()) % totp.interval,
    }


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
