"""Phase 5: auto-push admin User CRUD to enabled outbound SCIM targets.

Wires SQLAlchemy mapper events on `User` to capture inserts/updates/deletes,
then pushes them via ScimClient in a Flask `after_request` hook so we don't
hold the DB transaction open while doing outbound HTTP.

Gated by config_manager.SCIM_PUSH_ON_USER_CHANGE. When False (the default),
the listeners still register but the push step short-circuits.

Failed pushes are logged but never propagate — admin UX must not break when
an upstream SCIM target is unreachable.
"""
import json
from typing import Any

from flask import current_app, g, has_request_context, request
from sqlalchemy import event

from app.routes.scim.client import ScimClient, ScimClientError
from app.utils.config_manager import config_manager
from app.utils.logger_main import logger
from app.utils.models import User
from app.utils.models_scim import ScimTarget


_PENDING_ATTR = "_scim_pending_user_changes"


class _UserSnapshot:
    """A detached, dict-backed stand-in for User that ScimClient can read from.

    We can't safely hold an ORM object across after_commit; we snapshot the
    columns we need at event time.
    """

    __slots__ = ("id", "user_id", "username", "email", "first_name", "last_name", "active")

    def __init__(self, user: User):
        self.id = user.id
        self.user_id = user.user_id
        self.username = user.username
        self.email = user.email
        self.first_name = user.first_name
        self.last_name = user.last_name
        self.active = bool(user.active) if user.active is not None else True


def init_auto_sync(app):
    """Install the User → SCIM-target auto-sync pipeline.

    Called once from app/__init__.py when ENABLE_SCIM is true.
    """

    @event.listens_for(User, "after_insert")
    def _on_insert(mapper, connection, target):
        _stash("insert", target)

    @event.listens_for(User, "after_update")
    def _on_update(mapper, connection, target):
        _stash("update", target)

    @event.listens_for(User, "after_delete")
    def _on_delete(mapper, connection, target):
        # Snapshot before the row vanishes — we need email to find upstream.
        _stash("delete", target)

    @app.after_request
    def _flush(response):
        if not config_manager.SCIM_PUSH_ON_USER_CHANGE:
            _clear_pending()
            return response

        # Only sync changes triggered by admin user-management routes.
        # SCIM-server routes change users too, but those are pushes FROM
        # an upstream — re-pushing them out would be a loop.
        if not request.path.startswith("/admin/"):
            _clear_pending()
            return response

        pending = _take_pending()
        if not pending:
            return response

        targets = ScimTarget.query.filter_by(enabled=True).all()
        if not targets:
            return response

        for action, snapshot in pending:
            for target in targets:
                _push_one(target, action, snapshot)

        return response


# --- Internal helpers --------------------------------------------------------

def _stash(action: str, user: User) -> None:
    """Capture a snapshot of `user` on Flask's g so after_request can act on it."""
    if not has_request_context():
        # Triggered during app init / seeding — ignore.
        return
    try:
        snapshot = _UserSnapshot(user)
        pending = getattr(g, _PENDING_ATTR, None)
        if pending is None:
            pending = []
            setattr(g, _PENDING_ATTR, pending)
        pending.append((action, snapshot))
    except Exception as e:
        # Never break the originating CRUD because of sync stash issues.
        logger.warning("scim auto-sync stash failed: %s", e)


def _take_pending():
    pending = getattr(g, _PENDING_ATTR, None) or []
    if pending:
        setattr(g, _PENDING_ATTR, [])
    return pending


def _clear_pending():
    setattr(g, _PENDING_ATTR, [])


def _push_one(target: ScimTarget, action: str, snapshot: _UserSnapshot) -> None:
    try:
        with ScimClient(target) as c:
            if action in ("insert", "update"):
                c.upsert_user(snapshot)
            elif action == "delete":
                find_resp = c.find_user_by_username(snapshot.email)
                if find_resp.status_code != 200:
                    logger.warning(
                        "auto-sync delete: find failed (HTTP %s) for %s on %s",
                        find_resp.status_code, snapshot.email, target.name,
                    )
                    return
                try:
                    body = json.loads(find_resp.text)
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "auto-sync delete: malformed find response from %s",
                        target.name,
                    )
                    return
                resources = body.get("Resources") or []
                if not resources or "id" not in resources[0]:
                    # User wasn't on the remote — nothing to do.
                    return
                c.delete_user(resources[0]["id"], local_user_id=snapshot.id)
    except (ScimClientError, RuntimeError) as e:
        logger.warning(
            "auto-sync %s for %s -> %s failed: %s",
            action, snapshot.username, target.name, e,
        )
    except Exception:
        logger.exception(
            "Unexpected auto-sync error (%s for %s -> %s)",
            action, snapshot.username, target.name,
        )
