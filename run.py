import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from app import create_app
from app.utils.logger_main import log

# Get base directory dynamically
BASE_DIR = Path(__file__).parent


def load_certs():
    try:
        # Use default paths if environment variables are empty
        key_path = os.getenv("KEY_PATH") or str(
            BASE_DIR / "app" / "certs" / "idp-key.pem"
        )
        cert_path = os.getenv("CERT_PATH") or str(
            BASE_DIR / "app" / "certs" / "idp-cert.pem"
        )

        log.info(f"Loading key from: {key_path}")
        log.info(f"Loading cert from: {cert_path}")

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            log.info("✅ Private key loaded")
        with open(cert_path, "rb") as f:
            cert = f.read()
            log.info("✅ Certificate loaded")
        return key, cert
    except Exception as e:
        log.error(f"❌ Failed to load certs: {str(e)}")
        raise


key, cert = load_certs()
app = create_app()


if __name__ == "__main__":
    host = "10.1.1.200"
    port = int(os.getenv("IDP_PORT", 5000))

    cert_path = os.path.normpath(
        os.getenv("CERT_PATH", str(BASE_DIR / "app" / "certs" / "idp-cert.pem"))
    )
    key_path = os.path.normpath(
        os.getenv("KEY_PATH", str(BASE_DIR / "app" / "certs" / "idp-key.pem"))
    )

    app.run(
        host=host,
        port=port,
        debug=True,
        ssl_context=(cert_path, key_path),
        use_reloader=False,  # Disable reloader to avoid file locks
    )
