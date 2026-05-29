"""SCIM 2.0 server endpoints.

Discovery (/ServiceProviderConfig, /ResourceTypes, /Schemas) is unauthenticated
per RFC 7644 §4. Resource endpoints (/Users, /Groups) require a bearer token.
"""
import json

from flask import Response, request

from app.routes.scim import scim_bp
from app.routes.scim.auth import scim_token_required
from app.routes.scim.errors import scim_error, scim_response
from app.routes.scim.filters import (
    InvalidFilter,
    translate_user_filter,
    translate_group_filter,
)
from app.routes.scim.mappers import (
    USER_SCHEMA,
    GROUP_SCHEMA,
    InvalidResource,
    filter_attributes,
    group_location,
    group_to_scim,
    list_response,
    parse_attributes_param,
    scim_base_url,
    scim_to_new_group,
    scim_to_new_user,
    update_group_from_scim,
    update_user_from_scim,
    user_location,
    user_to_scim,
)
from app.routes.scim.patch import (
    PatchError,
    apply_user_patch,
    apply_group_patch,
)
from app.utils.models import db, User
from app.utils.models_scim import ScimGroup, ScimGroupMember


# Pagination defaults per RFC 7644 §3.4.2.4
DEFAULT_COUNT = 100
MAX_COUNT = 200


# --- Error handlers — unknown paths must still return SCIM-shaped JSON ------
#
# Blueprint-level @errorhandler does NOT catch unmatched URLs (Flask routes
# those at the app level before any blueprint takes over), so we install a
# catch-all route on the blueprint instead.

@scim_bp.route("/", defaults={"_unmatched": ""})
@scim_bp.route("/<path:_unmatched>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def _scim_unknown(_unmatched):
    """Last-resort 404 for any path under /scim/v2 with no specific route."""
    return scim_error(404, detail=f"Unknown SCIM resource: /{_unmatched}")


@scim_bp.errorhandler(405)
def _scim_405(_err):
    return scim_error(405, detail=f"Method {request.method} not allowed on this endpoint")


# --- Discovery endpoints (unauthenticated, per RFC 7644 §4) -----------------

@scim_bp.route("/ServiceProviderConfig", methods=["GET"])
def service_provider_config():
    """Advertise this server's SCIM capabilities (RFC 7644 §5)."""
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
        "patch":          {"supported": True},
        "bulk":           {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter":         {"supported": True, "maxResults": MAX_COUNT},
        "changePassword": {"supported": True},   # PATCH on password attribute works
        "sort":           {"supported": False},   # Phase 4 polish
        "etag":           {"supported": False},   # Phase 4 polish
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication via an opaque bearer token issued by the IdP admin",
            "specUri": "https://www.rfc-editor.org/info/rfc6750",
            "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644#section-2",
            "primary": True,
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{scim_base_url()}/ServiceProviderConfig",
        },
    }
    return scim_response(payload)


@scim_bp.route("/ResourceTypes", methods=["GET"])
def resource_types():
    """Return the User and Group resource type metadata."""
    base = scim_base_url()
    types = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": USER_SCHEMA,
            "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/User"},
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Group",
            "schema": GROUP_SCHEMA,
            "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/Group"},
        },
    ]
    return scim_response(list_response(types, total_results=len(types), start_index=1, items_per_page=len(types)))


@scim_bp.route("/ResourceTypes/<rt_id>", methods=["GET"])
def resource_type(rt_id):
    base = scim_base_url()
    if rt_id == "User":
        return scim_response({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User", "name": "User", "endpoint": "/Users",
            "schema": USER_SCHEMA,
            "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/User"},
        })
    if rt_id == "Group":
        return scim_response({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group", "name": "Group", "endpoint": "/Groups",
            "schema": GROUP_SCHEMA,
            "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/Group"},
        })
    return scim_error(404, detail=f"Unknown resource type: {rt_id}")


@scim_bp.route("/Schemas", methods=["GET"])
def schemas():
    """Return the schema definitions for User and Group.

    Phase 1 returns minimal but valid schema docs sufficient for discovery
    clients (Entra, Okta) to confirm the server's surface.
    """
    schemas_list = [_user_schema_doc(), _group_schema_doc()]
    return scim_response(list_response(schemas_list, total_results=len(schemas_list), start_index=1, items_per_page=len(schemas_list)))


@scim_bp.route("/Schemas/<path:schema_uri>", methods=["GET"])
def schema_one(schema_uri):
    if schema_uri == USER_SCHEMA:
        return scim_response(_user_schema_doc())
    if schema_uri == GROUP_SCHEMA:
        return scim_response(_group_schema_doc())
    return scim_error(404, detail=f"Unknown schema: {schema_uri}")


# --- /Users (read) ----------------------------------------------------------

@scim_bp.route("/Users", methods=["GET"])
@scim_token_required
def list_users():
    """List users with optional filter and pagination (RFC 7644 §3.4.2)."""
    try:
        start_index, count = _pagination_params()
    except InvalidFilter as e:
        return scim_error(400, scim_type="invalidValue", detail=str(e))

    query = User.query

    filter_str = request.args.get("filter")
    if filter_str:
        try:
            clause = translate_user_filter(filter_str)
        except InvalidFilter as e:
            return scim_error(400, scim_type="invalidFilter", detail=str(e))
        if clause is not None:
            query = query.filter(clause)

    attrs = parse_attributes_param(request.args.get("attributes"))
    excl = parse_attributes_param(request.args.get("excludedAttributes"))

    total = query.count()
    rows = query.order_by(User.id).offset(start_index - 1).limit(count).all()
    resources = [filter_attributes(user_to_scim(u), attrs, excl) for u in rows]
    return scim_response(list_response(resources, total_results=total, start_index=start_index, items_per_page=len(resources)))


@scim_bp.route("/Users/.search", methods=["POST"])
@scim_token_required
def search_users():
    """RFC 7644 §3.4.3 — POST search Users only."""
    return _search(body=_parse_scim_body(), resource_kinds=("user",))


@scim_bp.route("/.search", methods=["POST"])
@scim_token_required
def search_all():
    """RFC 7644 §3.4.3 — POST .search at root searches across all resource types."""
    return _search(body=_parse_scim_body(), resource_kinds=("user", "group"))


@scim_bp.route("/Groups/.search", methods=["POST"])
@scim_token_required
def search_groups():
    """RFC 7644 §3.4.3 — POST search Groups only."""
    return _search(body=_parse_scim_body(), resource_kinds=("group",))


def _search(body, resource_kinds):
    """Unified handler for /.search, /Users/.search, /Groups/.search.

    resource_kinds: iterable subset of {"user", "group"} controlling which
    tables to include in results.
    """
    if isinstance(body, Response):
        return body
    filter_str = body.get("filter")
    try:
        start_index = max(1, int(body.get("startIndex") or 1))
        count = min(MAX_COUNT, max(0, int(body.get("count") or DEFAULT_COUNT)))
    except (TypeError, ValueError):
        return scim_error(400, "invalidValue", "startIndex and count must be integers")
    attrs = body.get("attributes")
    excl = body.get("excludedAttributes")

    resources = []

    if "user" in resource_kinds:
        q = User.query
        if filter_str:
            try:
                clause = translate_user_filter(filter_str)
                if clause is not None:
                    q = q.filter(clause)
            except InvalidFilter:
                # Filter doesn't apply to User attributes — skip Users when
                # the search spans multiple resource kinds.
                if resource_kinds == ("user",):
                    return scim_error(400, "invalidFilter", "Filter does not parse against User attributes")
                q = q.filter(False)
        for u in q.order_by(User.id).all():
            resources.append(filter_attributes(user_to_scim(u), attrs, excl))

    if "group" in resource_kinds:
        q = ScimGroup.query
        if filter_str:
            try:
                clause = translate_group_filter(filter_str)
                if clause is not None:
                    q = q.filter(clause)
            except InvalidFilter:
                if resource_kinds == ("group",):
                    return scim_error(400, "invalidFilter", "Filter does not parse against Group attributes")
                q = q.filter(False)
        for g in q.order_by(ScimGroup.id).all():
            resources.append(filter_attributes(group_to_scim(g), attrs, excl))

    total = len(resources)
    paged = resources[start_index - 1 : start_index - 1 + count]
    return scim_response(list_response(paged, total_results=total, start_index=start_index, items_per_page=len(paged)))


@scim_bp.route("/Users/<scim_id>", methods=["GET"])
@scim_token_required
def get_user(scim_id):
    user = User.query.filter_by(user_id=scim_id).first()
    if user is None:
        return scim_error(404, detail=f"User {scim_id!r} not found")
    attrs = parse_attributes_param(request.args.get("attributes"))
    excl = parse_attributes_param(request.args.get("excludedAttributes"))
    return scim_response(filter_attributes(user_to_scim(user), attrs, excl))


@scim_bp.route("/Users", methods=["POST"])
@scim_token_required
def create_user():
    """RFC 7644 §3.3 — create. 201 + Location + body."""
    data = _parse_scim_body()
    if isinstance(data, Response):
        return data

    try:
        new_user = scim_to_new_user(data)
    except InvalidResource as e:
        return scim_error(400, e.scim_type, e.detail)

    if User.query.filter_by(username=new_user.username).first():
        return scim_error(409, "uniqueness", f"User with userName {new_user.username!r} already exists")
    if User.query.filter_by(email=new_user.email).first():
        return scim_error(409, "uniqueness", f"User with email {new_user.email!r} already exists")

    db.session.add(new_user)
    db.session.commit()

    return scim_response(
        user_to_scim(new_user),
        status=201,
        extra_headers={"Location": user_location(new_user)},
    )


@scim_bp.route("/Users/<scim_id>", methods=["PUT"])
@scim_token_required
def replace_user(scim_id):
    """RFC 7644 §3.5.1 — replace. 200 + body."""
    user = User.query.filter_by(user_id=scim_id).first()
    if user is None:
        return scim_error(404, detail=f"User {scim_id!r} not found")

    data = _parse_scim_body()
    if isinstance(data, Response):
        return data

    try:
        update_user_from_scim(user, data)
    except InvalidResource as e:
        db.session.rollback()
        return scim_error(400, e.scim_type, e.detail)

    # Uniqueness re-check on userName if it changed
    new_name = data.get("userName")
    if new_name and User.query.filter(User.username == new_name, User.id != user.id).first():
        db.session.rollback()
        return scim_error(409, "uniqueness", f"User with userName {new_name!r} already exists")

    db.session.commit()
    return scim_response(user_to_scim(user))


@scim_bp.route("/Users/<scim_id>", methods=["PATCH"])
@scim_token_required
def patch_user(scim_id):
    """RFC 7644 §3.5.2 — partial update via PatchOp."""
    user = User.query.filter_by(user_id=scim_id).first()
    if user is None:
        return scim_error(404, detail=f"User {scim_id!r} not found")

    data = _parse_scim_body()
    if isinstance(data, Response):
        return data

    operations = data.get("Operations") or data.get("operations") or []
    if not operations:
        return scim_error(400, "invalidValue", "PatchOp body must include a non-empty Operations array")

    try:
        apply_user_patch(user, operations)
    except PatchError as e:
        db.session.rollback()
        return scim_error(e.status, e.scim_type, e.detail)

    db.session.commit()

    if request.args.get("attributes"):
        return scim_response(user_to_scim(user))
    return Response(status=204)


@scim_bp.route("/Users/<scim_id>", methods=["DELETE"])
@scim_token_required
def delete_user(scim_id):
    """RFC 7644 §3.6 — hard delete. 204 No Content."""
    user = User.query.filter_by(user_id=scim_id).first()
    if user is None:
        return scim_error(404, detail=f"User {scim_id!r} not found")

    # Explicit cleanup since SQLite FKs aren't enforced by default
    ScimGroupMember.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    db.session.delete(user)
    db.session.commit()
    return Response(status=204)


# --- /Groups (read) ---------------------------------------------------------

@scim_bp.route("/Groups", methods=["GET"])
@scim_token_required
def list_groups():
    try:
        start_index, count = _pagination_params()
    except InvalidFilter as e:
        return scim_error(400, scim_type="invalidValue", detail=str(e))

    query = ScimGroup.query

    filter_str = request.args.get("filter")
    if filter_str:
        try:
            clause = translate_group_filter(filter_str)
        except InvalidFilter as e:
            return scim_error(400, scim_type="invalidFilter", detail=str(e))
        if clause is not None:
            query = query.filter(clause)

    attrs = parse_attributes_param(request.args.get("attributes"))
    excl = parse_attributes_param(request.args.get("excludedAttributes"))

    total = query.count()
    rows = query.order_by(ScimGroup.id).offset(start_index - 1).limit(count).all()
    resources = [filter_attributes(group_to_scim(g), attrs, excl) for g in rows]
    return scim_response(list_response(resources, total_results=total, start_index=start_index, items_per_page=len(resources)))


@scim_bp.route("/Groups/<scim_id>", methods=["GET"])
@scim_token_required
def get_group(scim_id):
    group = ScimGroup.query.filter_by(group_id=scim_id).first()
    if group is None:
        return scim_error(404, detail=f"Group {scim_id!r} not found")
    attrs = parse_attributes_param(request.args.get("attributes"))
    excl = parse_attributes_param(request.args.get("excludedAttributes"))
    return scim_response(filter_attributes(group_to_scim(group), attrs, excl))


@scim_bp.route("/Groups", methods=["POST"])
@scim_token_required
def create_group():
    data = _parse_scim_body()
    if isinstance(data, Response):
        return data

    try:
        new_group, member_uids = scim_to_new_group(data)
    except InvalidResource as e:
        return scim_error(400, e.scim_type, e.detail)

    if ScimGroup.query.filter_by(display_name=new_group.display_name).first():
        return scim_error(409, "uniqueness", f"Group with displayName {new_group.display_name!r} already exists")

    db.session.add(new_group)
    db.session.flush()  # populate new_group.id

    for uid in member_uids:
        target = User.query.filter_by(user_id=uid).first()
        if target is not None:
            db.session.add(ScimGroupMember(group_pk=new_group.id, user_id=target.id))

    db.session.commit()
    return scim_response(
        group_to_scim(new_group),
        status=201,
        extra_headers={"Location": group_location(new_group)},
    )


@scim_bp.route("/Groups/<scim_id>", methods=["PUT"])
@scim_token_required
def replace_group(scim_id):
    group = ScimGroup.query.filter_by(group_id=scim_id).first()
    if group is None:
        return scim_error(404, detail=f"Group {scim_id!r} not found")

    data = _parse_scim_body()
    if isinstance(data, Response):
        return data

    try:
        member_uids = update_group_from_scim(group, data)
    except InvalidResource as e:
        db.session.rollback()
        return scim_error(400, e.scim_type, e.detail)

    new_name = data.get("displayName")
    if new_name and ScimGroup.query.filter(ScimGroup.display_name == new_name, ScimGroup.id != group.id).first():
        db.session.rollback()
        return scim_error(409, "uniqueness", f"Group with displayName {new_name!r} already exists")

    # Replace members fully: drop existing then re-add. (PUT = full replace.)
    if "members" in data:
        ScimGroupMember.query.filter_by(group_pk=group.id).delete(synchronize_session=False)
        for uid in member_uids:
            target = User.query.filter_by(user_id=uid).first()
            if target is not None:
                db.session.add(ScimGroupMember(group_pk=group.id, user_id=target.id))

    db.session.commit()
    return scim_response(group_to_scim(group))


@scim_bp.route("/Groups/<scim_id>", methods=["PATCH"])
@scim_token_required
def patch_group(scim_id):
    group = ScimGroup.query.filter_by(group_id=scim_id).first()
    if group is None:
        return scim_error(404, detail=f"Group {scim_id!r} not found")

    data = _parse_scim_body()
    if isinstance(data, Response):
        return data

    operations = data.get("Operations") or data.get("operations") or []
    if not operations:
        return scim_error(400, "invalidValue", "PatchOp body must include a non-empty Operations array")

    try:
        apply_group_patch(group, operations)
    except PatchError as e:
        db.session.rollback()
        return scim_error(e.status, e.scim_type, e.detail)

    db.session.commit()

    if request.args.get("attributes"):
        return scim_response(group_to_scim(group))
    return Response(status=204)


@scim_bp.route("/Groups/<scim_id>", methods=["DELETE"])
@scim_token_required
def delete_group(scim_id):
    group = ScimGroup.query.filter_by(group_id=scim_id).first()
    if group is None:
        return scim_error(404, detail=f"Group {scim_id!r} not found")

    # ScimGroupMember.cascade="all, delete-orphan" on the relationship handles members
    db.session.delete(group)
    db.session.commit()
    return Response(status=204)


# --- Helpers ----------------------------------------------------------------

def _parse_scim_body():
    """Parse the request body as JSON; tolerate application/scim+json or application/json.

    Returns the parsed dict or a Response (a scim_error) — caller checks isinstance().
    """
    raw = request.get_data()
    if not raw:
        return scim_error(400, "invalidSyntax", "Empty request body")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        return scim_error(400, "invalidSyntax", f"Invalid JSON: {e}")


def _pagination_params():
    """Parse startIndex and count from query string per RFC 7644 §3.4.2.4."""
    try:
        start_index = int(request.args.get("startIndex", 1))
    except ValueError as e:
        raise InvalidFilter(f"startIndex must be an integer: {e}")
    try:
        count = int(request.args.get("count", DEFAULT_COUNT))
    except ValueError as e:
        raise InvalidFilter(f"count must be an integer: {e}")

    # Coerce out-of-range values per spec
    if start_index < 1:
        start_index = 1
    if count < 0:
        count = 0
    if count > MAX_COUNT:
        count = MAX_COUNT
    return start_index, count


def _user_schema_doc():
    """User schema per RFC 7643 §4.1."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": USER_SCHEMA,
        "name": "User",
        "description": "User account",
        "attributes": [
            _attr("userName", "string", required=True, uniqueness="server"),
            _complex_attr("name", [
                _attr("formatted", "string"),
                _attr("familyName", "string"),
                _attr("givenName", "string"),
            ]),
            _attr("displayName", "string"),
            _attr("active", "boolean"),
            _attr("externalId", "string", case_exact=True),
            _attr("password", "string", mutability="writeOnly", returned="never"),
            _multi_complex_attr("emails", [
                _attr("value", "string"),
                _attr("display", "string"),
                _attr("type", "string"),
                _attr("primary", "boolean"),
            ]),
            _multi_complex_attr("groups", [
                _attr("value", "string", mutability="readOnly"),
                _ref_attr("$ref", reference_types=["Group"], mutability="readOnly"),
                _attr("display", "string", mutability="readOnly"),
                _attr("type", "string", mutability="readOnly"),
            ], mutability="readOnly"),
        ],
        "meta": {"resourceType": "Schema", "location": f"{scim_base_url()}/Schemas/{USER_SCHEMA}"},
    }


def _group_schema_doc():
    """Group schema per RFC 7643 §4.2."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": GROUP_SCHEMA,
        "name": "Group",
        "description": "Group",
        "attributes": [
            _attr("displayName", "string", required=True),
            _attr("externalId", "string", case_exact=True),
            _multi_complex_attr("members", [
                _attr("value", "string"),
                _ref_attr("$ref", reference_types=["User", "Group"]),
                _attr("type", "string"),
                _attr("display", "string"),
            ]),
        ],
        "meta": {"resourceType": "Schema", "location": f"{scim_base_url()}/Schemas/{GROUP_SCHEMA}"},
    }


def _attr(name, type_, required=False, uniqueness="none",
          mutability="readWrite", returned="default", case_exact=False,
          multi_valued=False):
    """Simple-typed attribute (string, boolean, integer, ...)."""
    return {
        "name": name,
        "type": type_,
        "multiValued": multi_valued,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": returned,
        "uniqueness": uniqueness,
    }


def _ref_attr(name, reference_types, mutability="readWrite", required=False):
    """Reference-typed attribute. RFC 7643 §2.3.7 requires referenceTypes."""
    return {
        "name": name,
        "type": "reference",
        "referenceTypes": reference_types,
        "multiValued": False,
        "required": required,
        "caseExact": True,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": "none",
    }


def _complex_attr(name, sub_attrs):
    return {
        "name": name,
        "type": "complex",
        "multiValued": False,
        "required": False,
        "mutability": "readWrite",
        "returned": "default",
        "subAttributes": sub_attrs,
    }


def _multi_complex_attr(name, sub_attrs, mutability="readWrite"):
    return {
        "name": name,
        "type": "complex",
        "multiValued": True,
        "required": False,
        "mutability": mutability,
        "returned": "default",
        "subAttributes": sub_attrs,
    }
