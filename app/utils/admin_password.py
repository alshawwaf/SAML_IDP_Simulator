"""Admin portal password resolution.

Login order at verify time (not at boot — so the change takes effect
immediately without restarting the process):

  1. If /app/data/.admin-password-hash exists, compare against THAT hash.
     This is the override the admin sets via the Settings → Change Password
     form. Lives on the saml_idp_data volume so it survives redeploys.
  2. Otherwise, compare against config_manager.ADMIN_PASSWORD (env-or-default).

The hash file makes the override resilient — even if the file leaks, the
plaintext password isn't recoverable. We use werkzeug's PBKDF2-SHA256 which
the rest of the project already uses for SAML user passwords.
"""
import hmac

from werkzeug.security import generate_password_hash, check_password_hash

from app.utils.config_manager import config_manager
from app.utils.logger_main import logger


def verify_admin_password(presented: str) -> bool:
    """Return True if `presented` matches the active admin password."""
    if not presented:
        return False

    hash_file = config_manager.ADMIN_PASSWORD_HASH_FILE
    try:
        if hash_file.exists():
            stored_hash = hash_file.read_text().strip()
            if stored_hash:
                return check_password_hash(stored_hash, presented)
    except OSError as e:
        logger.warning(
            "Could not read admin password override at %s: %s. "
            "Falling back to env/default.", hash_file, e,
        )

    # Fallback: compare against the env-or-default plaintext, in constant time.
    return hmac.compare_digest(
        (config_manager.ADMIN_PASSWORD or "").encode("utf-8"),
        presented.encode("utf-8"),
    )


def set_admin_password(new_password: str) -> None:
    """Persist a new admin password (PBKDF2 hash) to the override file.

    Subsequent verify_admin_password() calls will use this hash and ignore
    the env-or-default value, with no process restart required.
    """
    if not new_password:
        raise ValueError("Password must not be empty")

    hash_file = config_manager.ADMIN_PASSWORD_HASH_FILE
    hash_file.parent.mkdir(parents=True, exist_ok=True)
    hash_file.write_text(generate_password_hash(new_password) + "\n")
    try:
        hash_file.chmod(0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX perms
    logger.info("Admin password updated and persisted to %s", hash_file)


def reset_to_default() -> None:
    """Remove the override file so the env-or-default password takes over again."""
    hash_file = config_manager.ADMIN_PASSWORD_HASH_FILE
    try:
        hash_file.unlink()
        logger.info("Admin password override removed; reverted to env/default")
    except FileNotFoundError:
        pass


def admin_password_overridden() -> bool:
    """True if the admin has set a custom password via the UI."""
    return config_manager.ADMIN_PASSWORD_HASH_FILE.exists()
