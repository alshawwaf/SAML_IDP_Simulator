import os
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from app import create_app
from app.utils.logger_main import log

BASE_DIR = Path(__file__).parent
KEY_PATH = os.getenv("KEY_PATH") or str(BASE_DIR / "app" / "certs" / "idp-key.pem")
CERT_PATH = os.getenv("CERT_PATH") or str(BASE_DIR / "app" / "certs" / "idp-cert.pem")


def generate_certificates():
    """Generate self-signed cert if missing (local mode)"""
    cert = Path(CERT_PATH)
    key = Path(KEY_PATH)

    if cert.exists() and key.exists():
        return

    print("🔐 Generating self-signed certificate (local)...")
    cert.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-days",
        "365",
        "-subj",
        f"/CN={os.getenv('IDP_HOST', 'localhost')}",
        "-addext",
        f"subjectAltName = DNS:{os.getenv('IDP_HOST', 'localhost')},IP:{os.getenv('IDP_HOST', '127.0.0.1')}",
    ]
    subprocess.run(cmd, check=True)
    print("✅ Certificate created (local)")


def load_certs():
    try:
        log.info(f"Loading cert from: {CERT_PATH}")
        log.info(f"Loading cert from: {CERT_PATH}")
        log.info(f"Loading cert from: {CERT_PATH}")
        with open(KEY_PATH, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            log.info("✅ Private key loaded")
        with open(CERT_PATH, "rb") as f:
            cert = f.read()
            log.info("✅ Certificate loaded")
        return key, cert
    except Exception as e:
        log.error(f"❌ Failed to load certs: {str(e)}", exc_info=True)
        raise


# Ensure certs exist before loading them
generate_certificates()
key, cert = load_certs()
app = create_app()

if __name__ == "__main__":
    host = os.getenv("IDP_HOST", "127.0.0.1")
    port = int(os.getenv("IDP_PORT", 5000))
    port = int(os.getenv("IDP_PORT", 5000))
    use_ssl = os.environ.get("ENABLE_SSL", "true").lower() == "true"
    if use_ssl:
        print("🔐 Starting with SSL...")
        app.run(host=host, port=port, ssl_context=(CERT_PATH, KEY_PATH))
    else:
        print("⚠️  Starting WITHOUT SSL (HTTP)...")
        app.run(host=host, port=port)
