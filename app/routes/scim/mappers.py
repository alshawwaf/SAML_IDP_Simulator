"""Map between database rows and SCIM 2.0 JSON resources.

Hand-rolled dict shaping (RFC 7643). Validation of incoming payloads is
lightweight: required fields and schema presence only.
"""
import secrets

from flask import request

from app.utils.config_manager import config_manager
from app.utils.models import User
from app.utils.models_scim import ScimGroup


class InvalidResource(ValueError):
    """Raised by inverse mappers when the SCIM body is malformed or incomplete."""

    def __init__(self, detail, scim_type="invalidValue"):
        super().__init__(detail)
        self.detail = detail
        self.scim_type = scim_type


USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


def _iso(dt):
    """ISO 8601 with UTC Z suffix, per RFC 7643 §2.3.5."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def scim_base_url():
    """Absolute base URL for SCIM resource Location/$ref values."""
    return request.url_root.rstrip("/") + config_manager.SCIM_BASE_PATH


def user_location(user):
    return f"{scim_base_url()}/Users/{user.user_id}"


def group_location(group):
    return f"{scim_base_url()}/Groups/{group.group_id}"


def user_to_scim(user: User) -> dict:
    """Map a User row to a SCIM User resource (RFC 7643 §4.1).

    Attributes whose backing storage is empty are omitted (not echoed with empty
    sub-values) — this is what RFC 7644 §3.5.2 PATCH-remove semantics require.
    """
    resource = {
        "schemas": [USER_SCHEMA],
        "id": user.user_id,
        "userName": user.username,
        "active": bool(user.active) if user.active is not None else True,
        "meta": {
            "resourceType": "User",
            "created": _iso(user.created_at),
            "lastModified": _iso(user.updated_at),
            "location": user_location(user),
        },
    }

    given = user.first_name or ""
    family = user.last_name or ""
    full_name = (given + " " + family).strip()
    if given or family:
        resource["name"] = {
            "givenName": given,
            "familyName": family,
            "formatted": full_name,
        }
        resource["displayName"] = full_name

    if user.email:
        resource["emails"] = [
            {"value": user.email, "type": "work", "primary": True}
        ]
    if user.external_id:
        resource["externalId"] = user.external_id
    return resource


# RFC 7644 §3.9 — attributes that are ALWAYS returned regardless of the
# `attributes`/`excludedAttributes` query parameters.
_ALWAYS_RETURNED = {"id", "schemas", "meta"}


def filter_attributes(resource: dict, attributes=None, excluded=None) -> dict:
    """Apply the `attributes` / `excludedAttributes` query params to a resource.

    Per RFC 7644 §3.9, `attributes` is an allow-list (plus the always-returned
    ones), and `excludedAttributes` is a deny-list. Sub-attribute paths
    (e.g. `name.familyName`) are normalized — Phase 1 supports top-level
    attribute filtering only.
    """
    if not attributes and not excluded:
        return resource

    def _top_level(p):
        return (p or "").split(".")[0].strip().lower()

    if attributes:
        wanted = {_top_level(p) for p in attributes if p}
        wanted |= {a.lower() for a in _ALWAYS_RETURNED}
        return {k: v for k, v in resource.items() if k.lower() in wanted}

    if excluded:
        unwanted = {_top_level(p) for p in excluded if p}
        unwanted -= {a.lower() for a in _ALWAYS_RETURNED}
        return {k: v for k, v in resource.items() if k.lower() not in unwanted}

    return resource


def parse_attributes_param(arg: str | None):
    """Split a comma-separated query-string param into a list of attribute names."""
    if not arg:
        return None
    return [s.strip() for s in arg.split(",") if s.strip()]


def group_to_scim(group: ScimGroup) -> dict:
    """Map a ScimGroup row to a SCIM Group resource (RFC 7643 §4.2)."""
    members = []
    for membership in group.members:
        target = User.query.get(membership.user_id)
        if target is None:
            continue
        members.append({
            "value": target.user_id,
            "$ref": user_location(target),
            "type": "User",
            "display": f"{target.first_name or ''} {target.last_name or ''}".strip() or target.username,
        })

    resource = {
        "schemas": [GROUP_SCHEMA],
        "id": group.group_id,
        "displayName": group.display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": _iso(group.created_at),
            "lastModified": _iso(group.updated_at),
            "location": group_location(group),
        },
    }
    if group.external_id:
        resource["externalId"] = group.external_id
    return resource


def list_response(resources, total_results, start_index, items_per_page):
    """RFC 7644 §3.4.2 ListResponse envelope."""
    return {
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total_results,
        "startIndex": start_index,
        "itemsPerPage": items_per_page,
        "Resources": resources,
    }


# --- Inverse mappers (SCIM JSON → DB rows) ---------------------------------

def _primary_email(emails):
    """Return the primary email value from a SCIM emails array, or first if no primary."""
    if not emails:
        return None
    for entry in emails:
        if isinstance(entry, dict) and entry.get("primary") and "value" in entry:
            return entry["value"]
    first = emails[0]
    if isinstance(first, dict):
        return first.get("value")
    return None


def scim_to_new_user(data: dict) -> User:
    """Build a new User from a POST /Users body. Does not commit."""
    if not isinstance(data, dict):
        raise InvalidResource("Request body must be a JSON object")

    schemas = data.get("schemas") or []
    if USER_SCHEMA not in schemas:
        raise InvalidResource(
            f"schemas array must include {USER_SCHEMA}", scim_type="invalidSyntax"
        )

    username = data.get("userName")
    if not username:
        raise InvalidResource("userName is required")

    primary_email = _primary_email(data.get("emails") or [])
    if not primary_email:
        # SCIM emails is optional (RFC 7643 §4.1) but our DB requires email NOT NULL
        # for SAML attribute statements. Synthesize one from userName so the row
        # is well-formed; if userName already looks email-shaped, use it directly.
        if "@" in username:
            primary_email = username
        else:
            primary_email = f"{username}@scim.local"

    name = data.get("name") or {}
    user = User(
        username=username,
        email=primary_email,
        first_name=(name.get("givenName") or "") if isinstance(name, dict) else "",
        last_name=(name.get("familyName") or "") if isinstance(name, dict) else "",
        external_id=data.get("externalId"),
        active=bool(data.get("active", True)),
    )
    # SCIM POST is allowed to omit password (writeOnly attribute, Phase 1 RFC 7643).
    # Generate a strong random one so the row meets the NOT NULL constraint.
    user.set_password(secrets.token_urlsafe(32))
    return user


def update_user_from_scim(user: User, data: dict) -> None:
    """Replace a User in-place from a PUT /Users/{id} body.

    Strict replace semantics: any field in the body overwrites the User's column.
    Fields absent from the body are kept as-is for columns where clearing would
    break NOT NULL constraints (email).
    """
    if not isinstance(data, dict):
        raise InvalidResource("Request body must be a JSON object")
    schemas = data.get("schemas") or []
    if USER_SCHEMA not in schemas:
        raise InvalidResource(
            f"schemas array must include {USER_SCHEMA}", scim_type="invalidSyntax"
        )

    if "userName" in data:
        if not data["userName"]:
            raise InvalidResource("userName cannot be empty")
        user.username = data["userName"]

    if "externalId" in data:
        user.external_id = data["externalId"] or None

    if "active" in data:
        user.active = bool(data["active"])

    if "name" in data and isinstance(data["name"], dict):
        user.first_name = data["name"].get("givenName") or ""
        user.last_name = data["name"].get("familyName") or ""

    if "emails" in data:
        new_email = _primary_email(data["emails"] or [])
        if new_email:
            user.email = new_email
        # If emails is present-but-empty, we keep the existing email (NOT NULL).

    if "password" in data and data["password"]:
        user.set_password(str(data["password"]))


def scim_to_new_group(data: dict) -> tuple[ScimGroup, list]:
    """Build a new ScimGroup from a POST /Groups body. Returns (group, member_user_ids)."""
    if not isinstance(data, dict):
        raise InvalidResource("Request body must be a JSON object")
    schemas = data.get("schemas") or []
    if GROUP_SCHEMA not in schemas:
        raise InvalidResource(
            f"schemas array must include {GROUP_SCHEMA}", scim_type="invalidSyntax"
        )

    display_name = data.get("displayName")
    if not display_name:
        raise InvalidResource("displayName is required")

    group = ScimGroup(
        display_name=display_name,
        external_id=data.get("externalId"),
    )
    member_uids = []
    for m in (data.get("members") or []):
        if isinstance(m, dict) and "value" in m:
            member_uids.append(m["value"])
    return group, member_uids


def update_group_from_scim(group: ScimGroup, data: dict) -> list:
    """Replace a ScimGroup in-place from a PUT /Groups/{id} body.

    Returns the list of member user_ids the body specifies (caller handles the
    join-table reconciliation since it requires a DB session).
    """
    if not isinstance(data, dict):
        raise InvalidResource("Request body must be a JSON object")
    schemas = data.get("schemas") or []
    if GROUP_SCHEMA not in schemas:
        raise InvalidResource(
            f"schemas array must include {GROUP_SCHEMA}", scim_type="invalidSyntax"
        )

    if "displayName" in data:
        if not data["displayName"]:
            raise InvalidResource("displayName cannot be empty")
        group.display_name = data["displayName"]

    if "externalId" in data:
        group.external_id = data["externalId"] or None

    member_uids = []
    if "members" in data:
        for m in (data["members"] or []):
            if isinstance(m, dict) and "value" in m:
                member_uids.append(m["value"])
    return member_uids
