#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

CERT_PATH = os.getenv("CERT_PATH", "app/certs/idp-cert.pem")
KEY_PATH = os.getenv("KEY_PATH", "app/certs/idp-key.pem")
IDP_HOST = os.getenv("IDP_HOST", "localhost")


def generate_certificates():
    """Generate self-signed certificate if missing"""
    cert = Path(CERT_PATH)
    key = Path(KEY_PATH)

    if cert.exists() and key.exists():
        print("🔐 Certificate already exists, skipping generation.")
        return

    print("🔐 Generating self-signed certificate...")
    cert.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
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
            f"/CN={IDP_HOST}",
            "-addext",
            f"subjectAltName = DNS:{IDP_HOST},IP:127.0.0.1",
        ],
        check=True,
    )

    print("✅ Certificate successfully created.")


def run_server():
    """Serve via gunicorn when USE_GUNICORN=true (the container default), else
    the Flask dev server. Falls back to Flask if gunicorn isn't installed
    (e.g. a minimal local checkout, or Windows where gunicorn is unsupported)."""
    if os.getenv("USE_GUNICORN", "false").lower() == "true":
        try:
            import gunicorn  # noqa: F401
            host = os.getenv("IDP_HOST", "0.0.0.0")
            port = os.getenv("IDP_PORT", "5000")
            workers = os.getenv("GUNICORN_WORKERS", "2")
            print(f"🧭 Starting gunicorn on {host}:{port} ({workers} workers)...")
            subprocess.run(
                ["gunicorn", "--bind", f"{host}:{port}",
                 "--workers", workers, "--access-logfile", "-", "run:app"],
                check=True,
            )
            return
        except ImportError:
            print("⚠️  USE_GUNICORN=true but gunicorn isn't installed — using the Flask server.")
    subprocess.run(["python", "run.py"], check=True)


def main():
    print("🚀 Starting SAML Identity Provider...")
    generate_certificates()
    run_server()


if __name__ == "__main__":
    main()
