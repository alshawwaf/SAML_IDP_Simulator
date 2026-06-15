"""Data models + helpers for the RADIUS / TACACS+ AAA simulators.

PURE ADDITIONS — new tables only. The existing User / SAML / SCIM models are
untouched. RADIUS and TACACS+ authenticate against the shared `User` directory;
these tables add per-user MFA (TOTP), the AAA auth log, and portal-editable
connection settings. Shared secrets and TOTP secrets are encrypted at rest.
"""
import io
import json
import os
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
    meta = db.Column(db.Text, nullable=True)   # JSON: rich per-event attributes for the detail modal

    def meta_dict(self):
        """Decoded `meta` (request/reply attributes, role, reason, …) or {}."""
        if not self.meta:
            return {}
        try:
            return json.loads(self.meta)
        except Exception:
            return {}


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
    # The address gateways / Gaia connect to. Blank = auto-detect (see
    # public_endpoint); set it to pin a NAT/floating IP or hostname.
    "public_host":      ("PUBLIC_HOST",      False, str),
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


# --- Reachable address (what gateways / Gaia point at) ---------------------
# RADIUS/UDP and TACACS+/TCP bypass the Traefik web domain and hit the host's
# public IP directly, so the portal resolves and shows that address. Detection
# asks an external "what's my IP" echo service (HTTPS, certs verified) — it only
# learns our own egress IP, no data is sent. Set PUBLIC_HOST (env or in-portal)
# to skip detection entirely for NAT/offline labs.
_PUBLIC_IP_SERVICES = (
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
)
_ip_cache = {"host": None, "source": None}  # per-worker; refreshed on demand


def _detect_public_ip(timeout=3):
    import ipaddress
    import urllib.request
    for url in _PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # TLS verified
                text = resp.read().decode("utf-8", "replace").strip()
            ip = text.split()[0] if text else ""
            ipaddress.ip_address(ip)  # rejects anything that isn't a valid IP
            return ip
        except Exception:
            continue
    return None


def public_endpoint(refresh=False, detect=True):
    """(host, source) that gateways / Gaia should connect to.

    A pinned `public_host` (in-portal setting or PUBLIC_HOST env) always wins.
    Otherwise the auto-detected IP is used, cached per worker; `refresh=True`
    re-detects. `detect=False` returns only what's already known (no network) so
    page renders stay instant — the page's JS calls back to fill/refresh it."""
    configured = get_setting("public_host")
    if configured:
        return configured, "configured"
    if detect and (refresh or not _ip_cache["host"]):
        ip = _detect_public_ip()
        if ip:
            _ip_cache.update(host=ip, source="auto-detected")
    return _ip_cache["host"], (_ip_cache["source"] or "unknown")


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


# --- Check Point Gaia role-based administration ----------------------------
# A user's Gaia role is decided by directory-group membership: anyone in an
# "admin" group gets the Gaia admin role, everyone else a read-only role. Tune
# without code via env vars (comma-separated, case-insensitive for the groups).
GAIA_ADMIN_GROUPS = {
    g.strip().lower()
    for g in os.environ.get(
        "GAIA_ADMIN_GROUPS", "admins,superadmins,superusers,administrators"
    ).split(",")
    if g.strip()
}
GAIA_ADMIN_ROLE = os.environ.get("GAIA_ADMIN_ROLE", "adminRole")    # built-in Gaia role
GAIA_USER_ROLE = os.environ.get("GAIA_USER_ROLE", "monitorRole")    # built-in read-only role


def is_gaia_admin(user):
    """True if the user belongs to a group that should map to a Gaia admin role."""
    names = {g.lower() for g in (getattr(user, "group_names", None) or [])}
    return bool(names & GAIA_ADMIN_GROUPS)


def gaia_radius_role(user):
    """(role_name, superuser_int) for the Check Point Gaia RADIUS VSAs
    (CP-Gaia-User-Role / CP-Gaia-SuperUser-Access)."""
    return (GAIA_ADMIN_ROLE, 1) if is_gaia_admin(user) else (GAIA_USER_ROLE, 0)


def gaia_tacacs_privlvl(user):
    """Privilege level for Gaia TACACS+. Gaia maps non-local users to a role
    named TACP-<priv-lvl> (priv-lvl 15 = full admin, 0 = the default TACP-0);
    it does NOT read role-name av-pairs, so priv-lvl is what matters for Gaia."""
    return 15 if is_gaia_admin(user) else 0


# --- helpers --------------------------------------------------------------
def user_aaa(user):
    return AaaUserAuth.query.filter_by(user_id=user.id).first() if user else None


def recent_aaa_logs(proto=None, limit=150):
    q = AaaLog.query.order_by(AaaLog.id.desc())
    if proto:
        q = q.filter_by(proto=proto)
    return q.limit(limit).all()


def log_event(proto, kind, username, nas, result, detail="", meta=None):
    try:
        db.session.add(AaaLog(
            proto=proto, kind=kind, username=username or "",
            nas=nas or "", result=result, detail=(detail or "")[:255],
            meta=json.dumps(meta, default=str) if meta else None,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
