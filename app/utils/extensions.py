"""Shared Flask extension singletons.

Kept in their own module so blueprints can import them without an import cycle
with app/__init__.py. Each is bound to the app via init_app() in create_app().
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Rate limiter. No global default limits — limits are opted-in per route (the
# login endpoints) so normal SAML / SCIM / admin traffic is never throttled.
# get_remote_address reads request.remote_addr, which ProxyFix populates with
# the real client IP from X-Forwarded-For. In-memory storage suits a
# single-instance demo deployment.
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
)
