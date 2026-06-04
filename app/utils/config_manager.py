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

# Exported singleton instance
config_manager = ConfigManager()
