"""Data models for the RADIUS / TACACS+ AAA simulators.

These are PURE ADDITIONS — new tables only. The existing User / SAML / SCIM
models are untouched, so the SAML flow cannot regress. RADIUS and TACACS+
authenticate against the shared `User` directory; these tables only add the
per-user AAA attributes (MFA/OTP) and the AAA auth log.
"""
from datetime import datetime

from app.utils.models import db


class AaaUserAuth(db.Model):
    """Per-user AAA attributes. Optional — a user with no row simply has MFA off.
    The OTP is a static, predictable demo passcode (not a real secret), kept in
    the clear so demos are repeatable; documented as such."""
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


def user_aaa(user):
    """Return the AaaUserAuth row for a User, or None."""
    return AaaUserAuth.query.filter_by(user_id=user.id).first() if user else None


def recent_aaa_logs(proto=None, limit=150):
    q = AaaLog.query.order_by(AaaLog.id.desc())
    if proto:
        q = q.filter_by(proto=proto)
    return q.limit(limit).all()


def log_event(proto, kind, username, nas, result, detail=""):
    """Write an AAA log row, committing on its own. Safe to call from the
    protocol threads; rolls back on error so it never kills a request."""
    try:
        db.session.add(AaaLog(
            proto=proto, kind=kind, username=username or "",
            nas=nas or "", result=result, detail=(detail or "")[:255],
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
