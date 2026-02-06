import os
from dotenv import load_dotenv
from pathlib import Path
from app.utils.path_config import BASE_DIR

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
        
        # Admin Credentials (CHANGE THESE IN PRODUCTION via environment variables)
        self.ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin@cpdemo.ca")
        self.ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Cpwins!1@2026")
        
        # Certificate Paths
        self.CERT_PATH = os.getenv("CERT_PATH", "app/certs/idp-cert.pem")
        self.KEY_PATH = os.getenv("KEY_PATH", "app/certs/idp-key.pem")
        
        # Logging & Monitoring
        self.GLITCHTIP_DSN = os.getenv("GLITCHTIP_DSN")
        
        # Service Provider Defaults
        self.DEFAULT_SP_ENTITY_ID = os.getenv("DEFAULT_SP_ENTITY_ID")
        self.DEFAULT_SP_ACS_URL = os.getenv("DEFAULT_SP_ACS_URL")

    def get_all_config(self):
        """Returns all configuration as a dictionary for template rendering"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

# Exported singleton instance
config_manager = ConfigManager()
