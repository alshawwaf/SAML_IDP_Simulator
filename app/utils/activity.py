"""App-wide audit logging — write one ActivityLog row per notable change.

`record()` never raises: auditing must never break the action it records.
Call it AFTER the route has committed its own change, so this commit doesn't
flush a half-finished transaction.
"""
import json

from flask import has_request_context, request, session

from app.utils.models import db, ActivityLog
from app.utils.config_manager import config_manager
from app.utils.logger_main import logger


def record(category, action, target=None, status="success", detail=None, actor=None):
    """Write an audit-log entry. Safe to call from any request handler.

    category: auth | user | service_provider | scim | saml | settings
    action:   human-readable summary ("Created user", "Admin login", …)
    target:   the affected object (username, SP name, token name, …)
    status:   success | error | info
    detail:   optional dict/str with extra context (dicts are JSON-encoded)
    actor:    override the actor (defaults to the admin username, or "system")
    """
    try:
        ip = method = path = None
        if actor is None:
            actor = "system"
            if has_request_context() and session.get("admin_logged_in"):
                actor = config_manager.ADMIN_USERNAME
        if has_request_context():
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            method = request.method
            path = request.path
        if detail is not None and not isinstance(detail, str):
            detail = json.dumps(detail, default=str, indent=2)
        db.session.add(ActivityLog(
            category=category, action=action, target=target, status=status,
            detail=detail, actor=actor, ip=ip, method=method, path=path,
        ))
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.warning("activity-log write failed for %s/%s", category, action, exc_info=True)
