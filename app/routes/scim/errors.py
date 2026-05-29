"""SCIM 2.0 response helpers — error envelope and content-type wrapper.

RFC 7644 §3.12 defines the error schema; §3.1 mandates application/scim+json.
"""
import json

from flask import Response


ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_CONTENT_TYPE = "application/scim+json"


def scim_response(payload, status=200, extra_headers=None):
    """Return a Flask Response with the SCIM content type and a JSON body."""
    body = json.dumps(payload, default=str)
    resp = Response(body, status=status, mimetype=SCIM_CONTENT_TYPE)
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v
    return resp


def scim_error(status, scim_type=None, detail=""):
    """Construct an RFC 7644 §3.12 error response.

    status is a string in the SCIM envelope, but Flask uses int for HTTP status.
    """
    body = {
        "schemas": [ERROR_SCHEMA],
        "status": str(status),
        "detail": detail or "",
    }
    if scim_type:
        body["scimType"] = scim_type
    return scim_response(body, status=status)
