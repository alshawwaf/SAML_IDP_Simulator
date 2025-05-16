#!/usr/bin/env python3
import os
from pathlib import Path
from app.utils.config_manager import IdPConfigManager
from lxml import etree
from signxml import XMLSigner, methods
import subprocess

DEBUG = os.getenv("DEBUG", "false").lower() == "true"
IDP_HOST = os.getenv("IDP_HOST", "localhost")
IDP_PORT = os.getenv("IDP_PORT", "5000")
DEFAULT_SP_ENTITY_ID = os.getenv("DEFAULT_SP_ENTITY_ID", "")
DEFAULT_SP_ACS_URL = os.getenv("DEFAULT_SP_ACS_URL", "")

CERT_PATH = os.getenv("CERT_PATH", "")
KEY_PATH = os.getenv("KEY_PATH", "")


def initialize_default_config():
    """Create default configuration if missing"""
    default_sp = {
        "entity_id": DEFAULT_SP_ENTITY_ID,
        "acs_url": DEFAULT_SP_ACS_URL,
    }
    default_config = {
        "entity_id": os.getenv("DEFAULT_ENTITY_ID", f"https://{IDP_HOST}:{IDP_PORT}"),
        "sso_service_url": os.getenv(
            "DEFAULT_SSO_SERVICE_URL", f"https://{IDP_HOST}:{IDP_PORT}/sso"
        ),
        "trusted_sp": [default_sp],
        "signing_cert_path": CERT_PATH,
        "signing_key_path": KEY_PATH,
    }

    config_path = Path("/app/config/dynamic-idp-config.yaml")

    # check if local or docker deployment
    if not is_running_in_docker():
        os.environ["APP_BASE_PATH"] = str(Path(__file__).parent.parent)

    if not config_path.exists():
        print("Initializing default IDP configuration...")
        IdPConfigManager.update_config(default_config)
        print(f"Default config created at {config_path}")
    else:
        print("Existing configuration found, skipping default initialization")


def validate_metadata(xml_path):
    from lxml import etree

    try:
        etree.parse(xml_path)
        return True
    except Exception as e:
        print(f"Invalid metadata XML: {str(e)}")
        return False


def sign_metadata(input_path, output_path, key_path):
    """Sign SAML metadata using signxml"""
    with open(input_path, "rb") as f:
        unsigned_metadata = etree.parse(f)

    with open(key_path, "rb") as f:
        private_key = f.read()

    signed_metadata = XMLSigner(
        method=methods.enveloped,  # Now methods is defined
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    ).sign(unsigned_metadata, key=private_key)

    with open(output_path, "wb") as f:
        f.write(etree.tostring(signed_metadata, pretty_print=True))


def main():
    print("=== Starting SAML Identity Provider ===")

    # 1. Generate certificates FIRST
    if not all(
        os.path.exists(f"/app/certs/{f}") for f in ["idp-key.pem", "idp-cert.pem"]
    ):
        subprocess.run(["/app/scripts/generate_certs.sh"], check=True)

    # 2. Initialize configuration
    initialize_default_config()

    # 3. Validate configuration
    try:
        config = IdPConfigManager.get_config()
        if not IdPConfigManager.validate_config(config):
            raise RuntimeError("Invalid base configuration")

        # Additional certificate validation
        if not os.path.exists(config["signing_cert_path"]):
            raise RuntimeError("Certificate file missing")

    except Exception as e:
        print(f"Configuration error: {str(e)}")
        exit(1)

    # Metadata initialization (existing logic)
    os.makedirs("/app/config/idps", exist_ok=True)

    # Start application
    print("--- Starting Application ---")
    subprocess.run(["python", "/app/run.py"])


# Add this to your app initialization
def is_running_in_docker():
    return os.path.exists("/.dockerenv")


if __name__ == "__main__":
    main()
