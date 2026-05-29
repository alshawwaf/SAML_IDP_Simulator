"""SCIM 2.0 outbound client — pushes users/groups to a remote SCIM server.

Production target: Check Point Check Point SASE at https://api.perimeter81.com/api/scim
(or the EU/AU/IN regional sibling). Works against any RFC 7644 SCIM 2.0 server.

Every request is logged to ScimPushLog so admins can inspect the wire shape
during demos — invaluable when explaining what SCIM provisioning actually sends.

Outbound mapping follows Generic SCIM 2.0 with the one universal Check Point SASE
quirk baked in: userName = email. (Check Point SASE requires it; most other
servers accept it.)
"""
import json
import time

import httpx

from app.routes.scim.mappers import GROUP_SCHEMA, USER_SCHEMA
from app.utils.crypto import decrypt_token
from app.utils.models import db, User
from app.utils.models_scim import ScimGroup, ScimPushLog, ScimTarget


PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class ScimClientError(Exception):
    """Wraps transport-level failures (timeouts, DNS, TLS). HTTP non-2xx is NOT an error here."""


class ScimClient:
    """Outbound SCIM client bound to a single ScimTarget.

    Use as a context manager to ensure the underlying httpx.Client is closed.
    """

    def __init__(self, target: ScimTarget, transport=None, timeout: float = 30.0):
        self.target = target
        self._token = decrypt_token(target.bearer_token_encrypted)
        self.client = httpx.Client(
            base_url=target.base_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/scim+json",
                "Accept": "application/scim+json",
            },
            timeout=timeout,
            transport=transport,
        )

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self.client.close()

    # --- Discovery / health ------------------------------------------------

    def test_connection(self):
        """Confirm the URL + token reach a working SCIM server.

        Tries /ServiceProviderConfig first (lightest probe). Discovery
        endpoints are OPTIONAL per RFC 7644 §4 and some servers — notably
        Check Point Check Point SASE — don't expose them. On 404 we fall back
        to /Users?count=0 which is mandatory per RFC 7644 §3.4.2 and
        returns just the totalResults metadata without any actual rows.
        """
        resp = self._request("GET", "/ServiceProviderConfig", operation="DISCOVERY_PING")
        if resp.status_code == 404:
            resp = self._request(
                "GET", "/Users?count=0",
                operation="DISCOVERY_PING_FALLBACK",
            )
        return resp

    # --- User operations ---------------------------------------------------

    def find_user_by_username(self, username):
        """RFC 7644 §3.4.2.2 — `userName eq "..."` filter for upsert correlation."""
        return self._request(
            "GET",
            f'/Users?filter=userName eq "{username}"',
            operation="FIND_USER",
        )

    def create_user(self, user: User):
        body = self._user_payload(user)
        return self._request(
            "POST", "/Users",
            json_body=body, operation="CREATE_USER", user_id=user.id,
        )

    def patch_user(self, user: User, upstream_id: str):
        """Replace writable attrs on the upstream user (idempotent PATCH-replace)."""
        body = {
            "schemas": [PATCH_OP_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "name.givenName", "value": user.first_name or ""},
                {"op": "replace", "path": "name.familyName", "value": user.last_name or ""},
                {"op": "replace", "path": "active", "value": bool(user.active)},
                {"op": "replace", "path": "externalId", "value": user.user_id},
            ],
        }
        return self._request(
            "PATCH", f"/Users/{upstream_id}",
            json_body=body, operation="PATCH_USER", user_id=user.id,
        )

    def delete_user(self, upstream_id: str, local_user_id=None):
        return self._request(
            "DELETE", f"/Users/{upstream_id}",
            operation="DELETE_USER", user_id=local_user_id,
        )

    def upsert_user(self, user: User):
        """Find-or-create-or-update flow.

        Returns (action, response):
          action ∈ {"created", "updated", "find_failed"}
        """
        find = self.find_user_by_username(user.email)
        if find.status_code != 200:
            return "find_failed", find

        body = _parse_json(find.text)
        total = body.get("totalResults", 0) if isinstance(body, dict) else 0

        if total == 0:
            return "created", self.create_user(user)

        resources = body.get("Resources", [])
        if not resources or "id" not in resources[0]:
            # Server said totalResults>0 but didn't include Resources — treat as find_failed
            return "find_failed", find

        upstream_id = resources[0]["id"]
        return "updated", self.patch_user(user, upstream_id)

    # --- Group operations --------------------------------------------------

    def find_group_by_displayname(self, display_name):
        return self._request(
            "GET",
            f'/Groups?filter=displayName eq "{display_name}"',
            operation="FIND_GROUP",
        )

    def create_group(self, group: ScimGroup, member_upstream_ids=None):
        members = []
        for uid in (member_upstream_ids or []):
            members.append({"value": uid, "type": "User"})
        body = {
            "schemas": [GROUP_SCHEMA],
            "displayName": group.display_name,
            "externalId": group.external_id or group.group_id,
            "members": members,
        }
        return self._request(
            "POST", "/Groups",
            json_body=body, operation="CREATE_GROUP", group_id=group.id,
        )

    def patch_group_add_members(self, upstream_group_id: str, upstream_user_ids: list, local_group_id=None):
        body = {
            "schemas": [PATCH_OP_SCHEMA],
            "Operations": [{
                "op": "add",
                "path": "members",
                "value": [{"value": uid} for uid in upstream_user_ids],
            }],
        }
        return self._request(
            "PATCH", f"/Groups/{upstream_group_id}",
            json_body=body, operation="ADD_GROUP_MEMBERS", group_id=local_group_id,
        )

    def patch_group_remove_members(self, upstream_group_id: str, upstream_user_ids: list, local_group_id=None):
        # Use the spec form with a filter — works against any compliant server,
        # including our own.
        body = {
            "schemas": [PATCH_OP_SCHEMA],
            "Operations": [
                {"op": "remove", "path": f'members[value eq "{uid}"]'}
                for uid in upstream_user_ids
            ],
        }
        return self._request(
            "PATCH", f"/Groups/{upstream_group_id}",
            json_body=body, operation="REMOVE_GROUP_MEMBERS", group_id=local_group_id,
        )

    def delete_group(self, upstream_group_id: str, local_group_id=None):
        return self._request(
            "DELETE", f"/Groups/{upstream_group_id}",
            operation="DELETE_GROUP", group_id=local_group_id,
        )

    # --- Internals ---------------------------------------------------------

    def _user_payload(self, user: User) -> dict:
        return {
            "schemas": [USER_SCHEMA],
            "userName": user.email,           # Check Point SASE convention: userName = email
            "externalId": user.user_id,       # our local UUID becomes the upstream externalId
            "name": {
                "givenName": user.first_name or "",
                "familyName": user.last_name or "",
            },
            "emails": [{"value": user.email, "type": "work", "primary": True}],
            "active": bool(user.active),
        }

    def _request(self, method, path, *, json_body=None, operation, user_id=None, group_id=None):
        """Send an HTTP request and log it. Returns the httpx.Response.

        Logs both transport errors (raises ScimClientError) and HTTP errors
        (does NOT raise — caller inspects status_code).
        """
        full_url = f"{self.target.base_url.rstrip('/')}{path}"
        body_str = json.dumps(json_body) if json_body is not None else None

        log = ScimPushLog(
            target_id=self.target.id,
            user_id=user_id,
            group_id=group_id,
            operation=operation,
            request_method=method,
            request_url=full_url,
            request_body=body_str,
        )

        start = time.time()
        try:
            resp = self.client.request(
                method, path,
                content=body_str.encode("utf-8") if body_str is not None else None,
            )
        except httpx.RequestError as e:
            log.duration_ms = int((time.time() - start) * 1000)
            log.error = f"{type(e).__name__}: {e}"
            db.session.add(log)
            db.session.commit()
            raise ScimClientError(f"Transport error against {full_url}: {e}") from e

        log.duration_ms = int((time.time() - start) * 1000)
        log.status_code = resp.status_code
        # Cap stored response body so a malicious/buggy server can't bloat the audit log
        log.response_body = (resp.text or "")[:10_000]
        if resp.status_code >= 400:
            log.error = f"HTTP {resp.status_code}"
        db.session.add(log)
        db.session.commit()
        return resp


def _parse_json(text):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
