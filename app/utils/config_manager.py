import os
from app.utils.logger_main import log
from pathlib import Path
from urllib.parse import urlparse


class IdPConfigManager:

    @staticmethod
    def get_config():
        cert_path = os.getenv("CERT_PATH", "app/certs/idp-cert.pem")
        key_path = os.getenv("KEY_PATH", "app/certs/idp-key.pem")

        entity_id = os.getenv("DEFAULT_ENTITY_ID", "https://localhost:5000")
        sso_service_url = os.getenv(
            "DEFAULT_SSO_SERVICE_URL", "https://localhost:5000/sso"
        )
        default_sp_entity_id = os.getenv("DEFAULT_SP_ENTITY_ID", "")
        default_sp_acs_url = os.getenv("DEFAULT_SP_ACS_URL", "")

        config = {
            "entity_id": entity_id,
            "sso_service_url": sso_service_url,
            "signing_cert_path": cert_path,
            "signing_key_path": key_path,
            "trusted_sp": [
                {"entity_id": default_sp_entity_id, "acs_url": default_sp_acs_url}
            ],
        }

        log.info(f"✅ Loaded config with cert: {cert_path}, key: {key_path}")
        return config

    @staticmethod
    def validate_config(config):
        required = [
            "entity_id",
            "sso_service_url",
            "signing_cert_path",
            "signing_key_path",
            "trusted_sp",
        ]
        missing = [k for k in required if k not in config]
        if missing:
            raise ValueError(f"Missing config fields: {missing}")

        for path_key in ["signing_cert_path", "signing_key_path"]:
            if not Path(config[path_key]).exists():
                raise FileNotFoundError(f"{path_key} not found: {config[path_key]}")

        for url_key in ["entity_id", "sso_service_url"]:
            parsed = urlparse(config[url_key])
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError(f"Invalid URL format in config: {url_key}")

        return True
