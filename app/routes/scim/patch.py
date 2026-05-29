"""PatchOp interpreter for SCIM Users and Groups (RFC 7644 §3.5.2).

The trickiest part of SCIM. Real clients deviate from the spec in well-known
ways and a robust IdP must accept both shapes.

Quirks handled:
  - Case-insensitive op names (Azure AD sends "Add", "Replace", "Op")
  - Capitalized "Operations" vs "operations"
  - Boolean-as-string ("True", "False" for active)
  - Entra-style group-member remove: {op: remove, path: "members",
    value: [{value: "user-id"}]} instead of the spec form
    {op: remove, path: "members[value eq \"user-id\"]"}
  - Single-element value when array expected

Out of scope for Phase 2:
  - Extension URN-prefixed paths (enterprise:2.0:User:department)
  - PUT-vs-PATCH on complex attribute replacement (we accept both)
"""
import re
from typing import Any

from app.utils.models import db, User
from app.utils.models_scim import ScimGroup, ScimGroupMember


# Matches a SCIM value-filter selector: members[value eq "..."], emails[type eq "work"], etc.
_FILTER_RE = re.compile(r'^([\w.]+)\[([\w.]+)\s+eq\s+"([^"]*)"\]$', re.IGNORECASE)


class PatchError(Exception):
    """Raised by the patch interpreter. The HTTP layer maps to RFC 7644 §3.12 errors."""

    def __init__(self, scim_type: str, detail: str, status: int = 400):
        super().__init__(detail)
        self.scim_type = scim_type
        self.detail = detail
        self.status = status


# --- Public API -------------------------------------------------------------

def apply_user_patch(user: User, operations: list) -> None:
    """Apply a list of PatchOp Operations to a User. Mutates in place.

    Caller is responsible for committing or rolling back the DB session.
    """
    for raw in operations:
        op, path, value = _normalize_operation(raw)
        _dispatch_user(user, op, path, value)


def apply_group_patch(group: ScimGroup, operations: list) -> None:
    """Apply a list of PatchOp Operations to a Group. Mutates in place."""
    for raw in operations:
        op, path, value = _normalize_operation(raw)
        _dispatch_group(group, op, path, value)


# --- Operation normalization ------------------------------------------------

def _normalize_operation(operation: dict) -> tuple[str, str | None, Any]:
    """Return (op, path, value) with case-normalized fields.

    Tolerates the capitalized variants Azure AD sometimes sends.
    """
    if not isinstance(operation, dict):
        raise PatchError("invalidValue", "Each Operation must be a JSON object")

    # Op name — lenient on casing
    op_raw = operation.get("op") or operation.get("Op")
    if op_raw is None:
        raise PatchError("invalidValue", "Operation is missing 'op'")
    op = str(op_raw).lower()
    if op not in ("add", "replace", "remove"):
        raise PatchError("invalidValue", f"Unsupported op: {op_raw!r}")

    path = operation.get("path") or operation.get("Path")
    value = operation["value"] if "value" in operation else operation.get("Value")

    return op, path, value


# --- User dispatch ----------------------------------------------------------

def _dispatch_user(user: User, op: str, path: str | None, value: Any) -> None:
    if op == "remove":
        if not path:
            raise PatchError("noTarget", "remove operation requires a path")
        _set_user_attr(user, path, None, removing=True)
        return

    # add / replace
    if not path:
        # Path-less add/replace: value must be an object whose keys are the paths
        if not isinstance(value, dict):
            raise PatchError("invalidValue", f"{op!r} without path requires a value object")
        for k, v in value.items():
            _set_user_attr(user, k, v, removing=False)
        return

    _set_user_attr(user, path, value, removing=False)


def _set_user_attr(user: User, path: str, value: Any, removing: bool) -> None:
    """Update one User attribute by SCIM path.

    Supports: userName, externalId, active, displayName (ignored — derived),
    name, name.givenName, name.familyName, emails (multi shapes),
    emails[type eq "work"].value, password (writeOnly).
    """
    if path is None:
        raise PatchError("noTarget", "Path is required")

    # Bracketed filter path: emails[type eq "work"].value
    bracket_match = _FILTER_RE.match(path)
    if bracket_match:
        outer, _, _ = bracket_match.groups()
        if outer.lower() == "emails":
            _set_user_email(user, value if not removing else None)
            return
        raise PatchError("invalidPath", f"Unsupported bracketed path for User: {path}")

    # Dotted path with sub-attribute on emails: emails[type eq "work"].value
    if path.lower().startswith("emails[") and ".value" in path.lower():
        _set_user_email(user, value if not removing else None)
        return

    p = path.lower()

    if p == "username":
        if removing:
            raise PatchError("mutability", "userName cannot be removed")
        user.username = str(value)
    elif p == "externalid":
        user.external_id = None if removing else (str(value) if value is not None else None)
    elif p == "active":
        if removing:
            user.active = True   # reset to default rather than null
        else:
            user.active = _coerce_bool(value)
    elif p == "displayname":
        # derived from name; PATCH on it is best-effort no-op
        pass
    elif p == "name":
        if removing:
            user.first_name = ""
            user.last_name = ""
        elif isinstance(value, dict):
            if "givenName" in value:
                user.first_name = value["givenName"] or ""
            if "familyName" in value:
                user.last_name = value["familyName"] or ""
        else:
            raise PatchError("invalidValue", "name must be an object")
    elif p == "name.givenname":
        user.first_name = "" if removing else str(value or "")
    elif p == "name.familyname":
        user.last_name = "" if removing else str(value or "")
    elif p == "emails":
        _set_user_email(user, None if removing else value)
    elif p == "password":
        if removing:
            raise PatchError("mutability", "password cannot be removed via PATCH")
        user.set_password(str(value))
    else:
        raise PatchError("invalidPath", f"Unsupported User PATCH path: {path}")


def _set_user_email(user: User, value: Any) -> None:
    """Accept the many shapes a SCIM client may send for emails."""
    if value is None:
        # Removing emails is dangerous because email is required on the SAML side;
        # noop here rather than violate the model constraint.
        return
    if isinstance(value, str):
        user.email = value
        return
    if isinstance(value, dict):
        if "value" in value:
            user.email = value["value"]
        return
    if isinstance(value, list) and value:
        primary = next((e for e in value if isinstance(e, dict) and e.get("primary")), value[0])
        if isinstance(primary, dict) and "value" in primary:
            user.email = primary["value"]
        return
    raise PatchError("invalidValue", "emails must be a string, object, or list")


# --- Group dispatch ---------------------------------------------------------

def _dispatch_group(group: ScimGroup, op: str, path: str | None, value: Any) -> None:
    if op == "remove":
        if not path:
            raise PatchError("noTarget", "remove operation requires a path")
        _remove_group_attr(group, path, value)
        return

    # add / replace
    if not path:
        if not isinstance(value, dict):
            raise PatchError("invalidValue", f"{op!r} without path requires a value object")
        for k, v in value.items():
            _set_group_attr(group, k, v, op)
        return

    _set_group_attr(group, path, value, op)


def _set_group_attr(group: ScimGroup, path: str, value: Any, op: str) -> None:
    p = path.lower()
    if p == "displayname":
        group.display_name = str(value) if value is not None else group.display_name
    elif p == "externalid":
        group.external_id = str(value) if value is not None else None
    elif p == "members":
        _modify_members(group, value, replace=(op == "replace"))
    else:
        raise PatchError("invalidPath", f"Unsupported Group PATCH path: {path}")


def _remove_group_attr(group: ScimGroup, path: str, value: Any) -> None:
    # Filter-style: members[value eq "..."]
    bracket_match = _FILTER_RE.match(path)
    if bracket_match:
        outer, sub, target = bracket_match.groups()
        if outer.lower() == "members" and sub.lower() == "value":
            _remove_member_by_uid(group, target)
            return
        raise PatchError("invalidPath", f"Unsupported bracketed remove: {path}")

    p = path.lower()
    if p == "members":
        # Entra style: value is a list of {value: "..."} pointing at members to drop
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "value" in item:
                    _remove_member_by_uid(group, item["value"])
            return
        if isinstance(value, dict) and "value" in value:
            _remove_member_by_uid(group, value["value"])
            return
        if value is None:
            # Remove ALL members
            ScimGroupMember.query.filter_by(group_pk=group.id).delete(synchronize_session=False)
            return
        raise PatchError("invalidValue", "members remove value must be a list or object")

    if p == "externalid":
        group.external_id = None
        return
    if p == "displayname":
        raise PatchError("mutability", "displayName cannot be removed")

    raise PatchError("invalidPath", f"Unsupported Group remove path: {path}")


def _modify_members(group: ScimGroup, value: Any, replace: bool) -> None:
    """Add (and optionally first clear) members of a group."""
    if value is None:
        if replace:
            ScimGroupMember.query.filter_by(group_pk=group.id).delete(synchronize_session=False)
        return

    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise PatchError("invalidValue", "members value must be a list or object")

    if replace:
        ScimGroupMember.query.filter_by(group_pk=group.id).delete(synchronize_session=False)

    for item in value:
        if not isinstance(item, dict) or "value" not in item:
            raise PatchError("invalidValue", "Each member must be an object with a 'value' key")
        target = User.query.filter_by(user_id=item["value"]).first()
        if target is None:
            # Per spec spirit, silently skip unknown members rather than fail the whole patch.
            continue
        exists = ScimGroupMember.query.filter_by(group_pk=group.id, user_id=target.id).first()
        if exists is None:
            db.session.add(ScimGroupMember(group_pk=group.id, user_id=target.id))


def _remove_member_by_uid(group: ScimGroup, user_uid: str) -> None:
    target = User.query.filter_by(user_id=user_uid).first()
    if target is None:
        return
    ScimGroupMember.query.filter_by(
        group_pk=group.id, user_id=target.id
    ).delete(synchronize_session=False)


# --- Helpers ----------------------------------------------------------------

def _coerce_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        low = val.lower()
        if low in ("true", "1"):
            return True
        if low in ("false", "0"):
            return False
    if isinstance(val, int):
        return bool(val)
    raise PatchError("invalidValue", f"Cannot coerce {val!r} to boolean")
