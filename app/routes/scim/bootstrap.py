"""First-boot SCIM seed: encryption key derivation + default inbound token.

Goal: with ENABLE_SCIM=true and nothing else configured, the admin can log in
and immediately use SCIM without generating a token manually. The auto-seeded
token is logged once and written to a bootstrap file under /app/data/ so the
operator can copy it out of Dokploy logs or via SSH.
"""
import os
from pathlib import Path

from app.utils.config_manager import config_manager
from app.utils.crypto import generate_inbound_token, hash_inbound_token
from app.utils.logger_main import logger
from app.utils.models import db
from app.utils.models_scim import ScimInboundToken
from app.utils.path_config import BASE_DIR


BOOTSTRAP_TOKEN_FILE = BASE_DIR / "data" / ".scim-bootstrap-token"


def seed_default_scim_data():
    """If SCIM is enabled but no inbound tokens exist, create one.

    The raw token value is:
      1. logged to the application log (visible in `docker logs`/Dokploy)
      2. written to BOOTSTRAP_TOKEN_FILE with restrictive permissions
      3. surfaced as a banner in the SCIM admin UI on first view

    After the operator copies it, they can delete the file (or use the
    "Acknowledge" button in the admin UI).
    """
    if ScimInboundToken.query.count() > 0:
        # Already have at least one token — don't disturb existing setup.
        return

    # If IDP_SCIM_TOKEN is provided (e.g. by the installer, which generates it
    # and shares the SAME value with the SCIM client so the two match on a fresh
    # deploy with zero manual steps), seed exactly that token. Otherwise fall
    # back to a random one (standalone / manual use).
    env_token = os.getenv("IDP_SCIM_TOKEN", "").strip()
    raw_token = env_token or generate_inbound_token()
    record = ScimInboundToken(
        name="default (from IDP_SCIM_TOKEN env)" if env_token else "default (auto-generated)",
        token_hash=hash_inbound_token(raw_token),
        enabled=True,
    )
    db.session.add(record)
    db.session.commit()

    # Persist for out-of-band retrieval (SSH / Dokploy file browser).
    try:
        BOOTSTRAP_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        BOOTSTRAP_TOKEN_FILE.write_text(
            "# SCIM default inbound bearer token (auto-generated on first boot)\n"
            "# Use this as the Bearer token when an external SCIM client pushes to\n"
            f"# {config_manager.SCIM_BASE_PATH}/Users etc. Delete this file after\n"
            "# copying the token, or click 'Acknowledge' in the SCIM admin UI.\n"
            "\n"
            f"{raw_token}\n"
        )
        try:
            BOOTSTRAP_TOKEN_FILE.chmod(0o600)
        except OSError:
            pass  # Best-effort on platforms that don't support chmod (Windows)
    except OSError as e:
        logger.warning(
            "Could not persist SCIM bootstrap token to %s: %s. "
            "Read it from the log line below instead.",
            BOOTSTRAP_TOKEN_FILE, e,
        )

    # Log it once — visible in Dokploy / docker logs.
    logger.info("=" * 70)
    logger.info("SCIM default inbound bearer token (auto-generated)")
    logger.info("  Token: %s", raw_token)
    logger.info("  Bootstrap file: %s", BOOTSTRAP_TOKEN_FILE)
    logger.info("  Use as: Authorization: Bearer <token>")
    logger.info("  Manage at /admin/scim/inbound-tokens")
    logger.info("=" * 70)


def read_bootstrap_token():
    """Return the raw bootstrap token if the file still exists, else None."""
    try:
        text = BOOTSTRAP_TOKEN_FILE.read_text()
    except OSError:
        return None
    # File has a few comment lines followed by the token. Return last non-empty line.
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    return None


def clear_bootstrap_token():
    """Remove the bootstrap token file (called from the admin UI 'Acknowledge' action)."""
    try:
        BOOTSTRAP_TOKEN_FILE.unlink()
        return True
    except OSError:
        return False
