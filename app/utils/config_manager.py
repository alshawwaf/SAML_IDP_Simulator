import os
from dotenv import load_dotenv
from pathlib import Path
from app.utils.path_config import BASE_DIR

# Default admin password baked into the build. Documented in README + login
# page so the operator always knows what to start with. Avoids shell-escape
# characters (no `!`, no `$`, no quotes) so it survives any env-var pipeline.
DEFAULT_ADMIN_PASSWORD = "CpDemo2026"

# Optional override file. If the admin clicks "Change Password" in the admin
# Settings page, the new password is written here as a SHA-256 hash. Lives on
# the saml_idp_data volume so it survives Dokploy redeploys.
ADMIN_PASSWORD_HASH_FILE = BASE_DIR / "data" / ".admin-password-hash"

# Persisted Flask secret key. If SECRET_KEY isn't supplied via env, generate a
# strong random key ONCE and persist it on the data volume so it stays stable
# across redeploys — a stable key keeps admin sessions valid and lets the
# Fernet-encrypted SCIM tokens (whose key derives from SECRET_KEY) survive a
# restart. NEVER hardcode this value in source or compose.
SECRET_KEY_FILE = BASE_DIR / "data" / ".secret-key"


def _load_or_create_secret_key() -> str:
    import secrets
    try:
        if SECRET_KEY_FILE.exists():
            existing = SECRET_KEY_FILE.read_text().strip()
            if existing:
                return existing
    except OSError:
        pass
    new_key = secrets.token_urlsafe(48)
    try:
        SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        SECRET_KEY_FILE.write_text(new_key + "\n")
        SECRET_KEY_FILE.chmod(0o600)
    except OSError:
        # Read-only FS or no POSIX perms — fall back to an ephemeral key.
        # The app still runs; sessions just reset on restart.
        pass
    return new_key


class ConfigManager:
    def __init__(self):
        # Load environment variables from .env file in the root directory
        load_dotenv(BASE_DIR / ".env")

        # Server Configuration
        self.PORT = int(os.getenv("IDP_PORT", 9001))
        self.HOST = os.getenv("IDP_HOST", "0.0.0.0")
        self.ENABLE_SSL = os.getenv("ENABLE_SSL", "true").lower() == "true"
        self.DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

        # Security & Identity. Env var wins; otherwise a stable random key is
        # generated and persisted to the data volume (never hardcoded).
        self.SECRET_KEY = os.getenv("SECRET_KEY") or _load_or_create_secret_key()

        # Entity ID and SSO URL.
        # If the operator sets these env vars explicitly, we honor them verbatim.
        # If NOT set, we derive them from the real request host at use time (see
        # effective_entity_id / effective_sso_url) so a fresh deploy advertises
        # correct, reachable URLs (e.g. https://idp.example.com/sso) instead of
        # the internal container address. The attributes below are the static
        # fallbacks used only when there is no request context (e.g. CLI).
        _entity = os.getenv("IDP_ENTITY_ID")
        self.IDP_ENTITY_ID_EXPLICIT = bool(_entity)
        self.IDP_ENTITY_ID = _entity or "https://idp.simulator"

        _sso = os.getenv("SSO_SERVICE_URL")
        self.SSO_SERVICE_URL_EXPLICIT = bool(_sso)
        self.SSO_SERVICE_URL = _sso or f"http://{self.HOST}:{self.PORT}/sso"

        # Admin Credentials.
        # Resolution: ADMIN_USERNAME env var → fallback "admin@cpdemo.ca".
        # Password is resolved at login time (not here) so a UI password change
        # takes effect without a process restart — see verify_admin_password().
        self.ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin@cpdemo.ca")
        self.ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
        self.ADMIN_PASSWORD_HASH_FILE = ADMIN_PASSWORD_HASH_FILE
        self.ADMIN_PASSWORD_IS_DEFAULT = (self.ADMIN_PASSWORD == DEFAULT_ADMIN_PASSWORD
                                          and not ADMIN_PASSWORD_HASH_FILE.exists())
        
        # Certificate Paths
        self.CERT_PATH = os.getenv("CERT_PATH", "app/certs/idp-cert.pem")
        self.KEY_PATH = os.getenv("KEY_PATH", "app/certs/idp-key.pem")
        
        # Logging & Monitoring
        self.GLITCHTIP_DSN = os.getenv("GLITCHTIP_DSN")
        
        # Service Provider Defaults
        self.DEFAULT_SP_ENTITY_ID = os.getenv("DEFAULT_SP_ENTITY_ID")
        self.DEFAULT_SP_ACS_URL = os.getenv("DEFAULT_SP_ACS_URL")

        # SCIM 2.0 — ENABLED BY DEFAULT and toggleable at runtime from the admin
        # portal. The SCIM routes are always registered; scim_enabled() gates
        # them, so the toggle takes effect without a restart. The portal toggle
        # writes/removes a disable marker on the data volume. ENABLE_SCIM=false
        # forces SCIM off at the environment level (overrides the portal toggle).
        self.SCIM_DISABLED_MARKER = BASE_DIR / "data" / ".scim-disabled"
        self.SCIM_FORCED_OFF = os.getenv("ENABLE_SCIM", "").strip().lower() == "false"
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

        # AAA simulators (RADIUS / TACACS+). Shared secrets are demo defaults —
        # override via env for anything beyond a throwaway lab (same philosophy
        # as ADMIN_PASSWORD). RADIUS uses 1812/1813; TACACS+ binds an unprivileged
        # port inside the container (mapped to host 49 in compose) so we stay
        # non-root. AAA_DEFAULT_OTP is the predictable passcode for MFA demo users.
        self.RADIUS_SECRET = os.getenv("RADIUS_SECRET", "testing123")
        self.RADIUS_AUTH_PORT = int(os.getenv("RADIUS_AUTH_PORT", 1812))
        self.RADIUS_ACCT_PORT = int(os.getenv("RADIUS_ACCT_PORT", 1813))
        self.TACACS_SECRET = os.getenv("TACACS_SECRET", "testing123")
        self.TACACS_PORT = int(os.getenv("TACACS_PORT", 4949))
        self.AAA_DEFAULT_OTP = os.getenv("AAA_DEFAULT_OTP", "123456")
        self.AAA_BIND = os.getenv("AAA_BIND", "0.0.0.0")

    def effective_entity_id(self):
        """The Entity ID to advertise. Explicit env var wins; otherwise derive
        from the live request host so it matches the real deployment URL."""
        if self.IDP_ENTITY_ID_EXPLICIT:
            return self.IDP_ENTITY_ID
        try:
            from flask import has_request_context, request
            if has_request_context():
                return request.url_root.rstrip("/")
        except Exception:
            pass
        return self.IDP_ENTITY_ID

    def effective_sso_url(self):
        """The SSO endpoint URL to advertise. Explicit env var wins; otherwise
        derive from the live request host (…/sso) so SPs get a reachable URL."""
        if self.SSO_SERVICE_URL_EXPLICIT:
            return self.SSO_SERVICE_URL
        try:
            from flask import has_request_context, request
            if has_request_context():
                return request.url_root.rstrip("/") + "/sso"
        except Exception:
            pass
        return self.SSO_SERVICE_URL

    def get_all_config(self):
        """Returns all configuration as a dictionary for template rendering.

        Overlays the effective (request-derived) Entity ID / SSO URL so admin
        pages display the same values that get baked into metadata."""
        data = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        data["IDP_ENTITY_ID"] = self.effective_entity_id()
        data["SSO_SERVICE_URL"] = self.effective_sso_url()
        return data

    def scim_enabled(self) -> bool:
        """Runtime SCIM on/off — default ON. An admin can disable/re-enable it
        from the portal (toggles a marker file on the data volume); the SCIM
        routes are always registered, so the change needs no restart.
        ENABLE_SCIM=false forces it off and overrides the portal toggle."""
        if self.SCIM_FORCED_OFF:
            return False
        try:
            return not self.SCIM_DISABLED_MARKER.exists()
        except OSError:
            return True

    def set_scim_enabled(self, enabled: bool) -> None:
        """Persist the portal SCIM toggle via the disable marker file."""
        self.SCIM_DISABLED_MARKER.parent.mkdir(parents=True, exist_ok=True)
        if enabled:
            try:
                self.SCIM_DISABLED_MARKER.unlink()
            except FileNotFoundError:
                pass
        else:
            self.SCIM_DISABLED_MARKER.touch()


# Exported singleton instance
config_manager = ConfigManager()
