"""Translate SCIM 2.0 filter expressions into SQLAlchemy clause elements.

Uses scim2-filter-parser for lexing/parsing (handles the real grammar), then
walks the AST to emit ORM-native SQLAlchemy expressions.

Phase 1 supports:
  - Operators: eq, ne, co, sw, ew, pr, gt, ge, lt, le
  - Boolean composition: and, or, not
  - Top-level attributes on User and Group (see *_ATTR_MAP below)

Phase 2 will add:
  - Bracketed sub-attribute filters: emails[type eq "work" and value co "@example.com"]
  - Complex member filters on Group
"""
from sqlalchemy import and_, or_, not_

from scim2_filter_parser import ast
from scim2_filter_parser.lexer import SCIMLexer
from scim2_filter_parser.parser import SCIMParser, SCIMParserError

from app.utils.models import User
from app.utils.models_scim import ScimGroup


class InvalidFilter(Exception):
    """Raised when a filter cannot be parsed or translated.

    The HTTP layer catches this and returns 400 invalidFilter per RFC 7644 §3.12.
    """


# --- Attribute maps ----------------------------------------------------------
# Each entry maps a SCIM attribute path (canonical case as defined in RFC 7643)
# to a SQLAlchemy column. Comparisons on attribute *names* are case-insensitive
# per RFC 7644 §3.4.2.2 — handled by normalizing to lower-case in lookups.

USER_ATTR_MAP = {
    "id": User.user_id,
    "username": User.username,
    "externalid": User.external_id,
    "active": User.active,
    "emails.value": User.email,
    "name.givenname": User.first_name,
    "name.familyname": User.last_name,
    "meta.created": User.created_at,
    "meta.lastmodified": User.updated_at,
}

GROUP_ATTR_MAP = {
    "id": ScimGroup.group_id,
    "displayname": ScimGroup.display_name,
    "externalid": ScimGroup.external_id,
    "meta.created": ScimGroup.created_at,
    "meta.lastmodified": ScimGroup.updated_at,
    # members.value requires a subquery — handled separately in routes/server.py
}


def _attr_path_str(attr_path):
    """Canonical lower-case attribute path: 'name', 'name.familyname', etc."""
    name = attr_path.attr_name.lower()
    if attr_path.sub_attr is not None:
        name = f"{name}.{attr_path.sub_attr.value.lower()}"
    return name


def _coerce_value(column, raw):
    """Coerce a parsed filter literal to the column's Python type."""
    try:
        py_type = column.type.python_type
    except (AttributeError, NotImplementedError):
        py_type = str

    if py_type is bool:
        low = raw.lower()
        if low in ("true", "1"):
            return True
        if low in ("false", "0"):
            return False
        raise InvalidFilter(f"Cannot coerce {raw!r} to boolean")
    if py_type is int:
        try:
            return int(raw)
        except ValueError as e:
            raise InvalidFilter(f"Cannot coerce {raw!r} to integer") from e
    # Datetimes (meta.created, meta.lastModified) get ISO 8601 string compare
    # in Phase 1; Phase 2 will parse properly.
    return raw


def _translate_attr_expr(node, attr_map):
    name = _attr_path_str(node.attr_path)
    op = node.value.lower()

    column = attr_map.get(name)
    if column is None:
        raise InvalidFilter(f"Unsupported attribute: {node.attr_path.attr_name}")

    if op == "pr":
        # SCIM "present" — non-null AND non-empty-string for text columns.
        try:
            py_type = column.type.python_type
        except (AttributeError, NotImplementedError):
            py_type = str
        if py_type is str:
            return and_(column.isnot(None), column != "")
        return column.isnot(None)

    if node.comp_value is None:
        raise InvalidFilter(f"Operator '{op}' requires a comparison value")
    value = _coerce_value(column, node.comp_value.value)

    if op == "eq":
        return column == value
    if op == "ne":
        return column != value
    if op == "co":
        return column.ilike(f"%{value}%")
    if op == "sw":
        return column.ilike(f"{value}%")
    if op == "ew":
        return column.ilike(f"%{value}")
    if op == "gt":
        return column > value
    if op == "ge":
        return column >= value
    if op == "lt":
        return column < value
    if op == "le":
        return column <= value
    raise InvalidFilter(f"Unsupported operator: {op}")


def _translate(node, attr_map):
    """Walk a Filter/LogExpr/AttrExpr AST node."""
    if isinstance(node, ast.Filter):
        if node.namespace is not None:
            # `emails[type eq "work"]` syntax — Phase 2.
            raise InvalidFilter(
                f"Bracketed sub-attribute filter on '{node.namespace.attr_name}' "
                "is not yet supported. Use a flat path like 'emails.value eq \"x\"' instead."
            )
        clause = _translate(node.expr, attr_map)
        return not_(clause) if node.negated else clause

    if isinstance(node, ast.LogExpr):
        op = node.op.lower()
        left = _translate(node.expr1, attr_map)
        right = _translate(node.expr2, attr_map)
        if op == "and":
            return and_(left, right)
        if op == "or":
            return or_(left, right)
        raise InvalidFilter(f"Unsupported logical operator: {node.op}")

    if isinstance(node, ast.AttrExpr):
        return _translate_attr_expr(node, attr_map)

    raise InvalidFilter(f"Unsupported AST node: {type(node).__name__}")


def _parse(filter_str):
    try:
        tokens = SCIMLexer().tokenize(filter_str)
        tree = SCIMParser().parse(iter(tokens))
    except SCIMParserError as e:
        raise InvalidFilter(f"Filter syntax error: {e}") from e
    except Exception as e:
        # The lexer raises plain Exception on bad input
        raise InvalidFilter(f"Filter parse error: {e}") from e
    if tree is None:
        raise InvalidFilter("Empty or unparseable filter")
    return tree


def translate_user_filter(filter_str):
    """Return a SQLAlchemy clause that filters User rows per the SCIM expression."""
    if not filter_str:
        return None
    return _translate(_parse(filter_str), USER_ATTR_MAP)


def translate_group_filter(filter_str):
    """Return a SQLAlchemy clause that filters ScimGroup rows per the SCIM expression."""
    if not filter_str:
        return None
    return _translate(_parse(filter_str), GROUP_ATTR_MAP)
