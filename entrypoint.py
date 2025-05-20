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


def main():
    print("🚀 Starting SAML Identity Provider...")
    generate_certificates()
    subprocess.run(["python", "run.py"])


if __name__ == "__main__":
    main()
