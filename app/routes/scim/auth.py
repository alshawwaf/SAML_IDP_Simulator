"""Bearer-token auth for inbound SCIM server requests (RFC 7644 §2).

The /scim/v2 endpoints use opaque bearer tokens, not the Flask admin session,
so this decorator runs entirely outside the existing auth path.

Discovery endpoints (/ServiceProviderConfig, /ResourceTypes, /Schemas) are
intentionally unauthenticated per RFC 7644 §4 — real provisioning clients
(Entra, Okta) probe them before authenticating.
"""
from datetime import datetime
from functools import wraps

from flask import request

from app.utils.models import db
from app.utils.models_scim import ScimInboundToken
from app.utils.crypto import hash_inbound_token
from app.routes.scim.errors import scim_error


def scim_token_required(view):
    """Require a valid bearer token. Updates last_used_at on success."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return scim_error(401, detail="Missing or malformed Authorization header.")

        token = auth_header[7:].strip()
        if not token:
            return scim_error(401, detail="Empty bearer token.")

        # Lookup by SHA-256 hash. The hash itself is not secret, so direct
        # WHERE lookup is fine; the underlying token comparison happens via
        # hmac.compare_digest in crypto.verify_inbound_token.
        token_hash = hash_inbound_token(token)
        record = ScimInboundToken.query.filter_by(
            token_hash=token_hash, enabled=True
        ).first()
        if record is None:
            return scim_error(401, detail="Invalid or disabled bearer token.")

        record.last_used_at = datetime.utcnow()
        db.session.commit()

        return view(*args, **kwargs)

    return wrapped
