import os
import secrets
from dotenv import load_dotenv
from pathlib import Path
from app.utils.path_config import BASE_DIR

# Persistent location for the auto-generated admin password. Lives on the
# saml_idp_data volume in Docker (mounted at /app/data), so it survives
# redeploys. Operators can read it back via:
#   docker exec <container> cat /app/data/.admin-password
ADMIN_PASSWORD_FILE = BASE_DIR / "data" / ".admin-password"


def _resolve_admin_password():
    """Decide what the admin password should be on this boot.

    Resolution order:
      1. ADMIN_PASSWORD env var set explicitly → use it (operator override)
      2. /app/data/.admin-password exists       → read it (persisted from a
                                                  prior auto-generation)
      3. otherwise                              → generate a strong random
                                                  password, persist to file,
                                                  log it loudly

    Returns (password, was_auto_generated_this_boot).
    """
    explicit = os.getenv("ADMIN_PASSWORD")
    if explicit:
        return explicit, False

    # Try to read a previously persisted auto-generated password.
    try:
        if ADMIN_PASSWORD_FILE.exists():
            for line in reversed(ADMIN_PASSWORD_FILE.read_text().splitlines()):
                line = line.strip()
                if line and not line.startswith("#"):
                    return line, False
    except OSError:
        pass

    # Generate a fresh one and persist.
    new_pw = secrets.token_urlsafe(20)  # ~26 chars, URL-safe (no shell-escape risk)
    try:
        ADMIN_PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
        ADMIN_PASSWORD_FILE.write_text(
            "# Auto-generated admin portal password (first boot).\n"
            "# Lives on the saml_idp_data volume so it survives redeploys.\n"
            "# To lock in your own value, set ADMIN_PASSWORD in the Dokploy\n"
            "# Environment tab and redeploy.\n"
            "\n"
            f"{new_pw}\n"
        )
        try:
            ADMIN_PASSWORD_FILE.chmod(0o600)
        except OSError:
            pass  # best-effort on platforms without POSIX perms
    except OSError:
        # Filesystem write failed (e.g. read-only mount). The password is still
        # valid for this boot; operator must capture it from the startup log.
        pass

    return new_pw, True


class ConfigManager:
    def __init__(self):
        # Load environment variables from .env file in the root directory
        load_dotenv(BASE_DIR / ".env")

        # Server Configuration
        self.PORT = int(os.getenv("IDP_PORT", 9001))
        self.HOST = os.getenv("IDP_HOST", "0.0.0.0")
        self.ENABLE_SSL = os.getenv("ENABLE_SSL", "true").lower() == "true"
        self.DEBUG = os.getenv("FLASK_DEBUG", "True").lower() == "true"

        # Security & Identity
        self.SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-" + os.urandom(8).hex())
        self.IDP_ENTITY_ID = os.getenv("IDP_ENTITY_ID", "https://idp.simulator")
        self.SSO_SERVICE_URL = os.getenv("SSO_SERVICE_URL", f"http://{self.HOST}:{self.PORT}/sso")

        # Admin Credentials — see _resolve_admin_password() docstring.
        self.ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin@cpdemo.ca")
        self.ADMIN_PASSWORD, self.ADMIN_PASSWORD_AUTO_GENERATED = _resolve_admin_password()
        self.ADMIN_PASSWORD_FILE = ADMIN_PASSWORD_FILE
        
        # Certificate Paths
        self.CERT_PATH = os.getenv("CERT_PATH", "app/certs/idp-cert.pem")
        self.KEY_PATH = os.getenv("KEY_PATH", "app/certs/idp-key.pem")
        
        # Logging & Monitoring
        self.GLITCHTIP_DSN = os.getenv("GLITCHTIP_DSN")
        
        # Service Provider Defaults
        self.DEFAULT_SP_ENTITY_ID = os.getenv("DEFAULT_SP_ENTITY_ID")
        self.DEFAULT_SP_ACS_URL = os.getenv("DEFAULT_SP_ACS_URL")

        # SCIM 2.0 — disabled by default; SAML flow is unaffected when false.
        # Two ways to enable:
        #   1. ENABLE_SCIM=true env var (Dokploy Environment tab, .env file, etc.)
        #   2. Create a marker file at /app/data/.enable-scim (or BASE_DIR/data/.enable-scim
        #      locally) — useful when the env-var pipeline is broken or unavailable.
        env_enabled = os.getenv("ENABLE_SCIM", "false").lower() == "true"
        marker_path = BASE_DIR / "data" / ".enable-scim"
        self.ENABLE_SCIM = env_enabled or marker_path.exists()
        self.SCIM_BASE_PATH = os.getenv("SCIM_BASE_PATH", "/scim/v2")
        self.SCIM_PUSH_ON_USER_CHANGE = os.getenv("SCIM_PUSH_ON_USER_CHANGE", "false").lower() == "true"

        # Encryption key for outbound SCIM bearer tokens at rest.
        # If not explicitly set, derive a stable Fernet key from SECRET_KEY so
        # the operator only has to think about ENABLE_SCIM=true.
        explicit_scim_key = os.getenv("SCIM_ENCRYPTION_KEY")
        if explicit_scim_key:
            self.SCIM_ENCRYPTION_KEY = explicit_scim_key
            self.SCIM_ENCRYPTION_KEY_DERIVED = False
        else:
            import base64
            import hashlib
            derived = hashlib.sha256(
                (self.SECRET_KEY + "::scim-token-fernet-v1").encode("utf-8")
            ).digest()
            self.SCIM_ENCRYPTION_KEY = base64.urlsafe_b64encode(derived).decode("ascii")
            self.SCIM_ENCRYPTION_KEY_DERIVED = True

    def get_all_config(self):
        """Returns all configuration as a dictionary for template rendering"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

# Exported singleton instance
config_manager = ConfigManager()
