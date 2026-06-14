#!/usr/bin/env python3
import os
import signal
import subprocess
import sys
import time
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


def _spawn(cmd, label):
    print(f"▶  starting {label}: {' '.join(cmd)}", flush=True)
    return subprocess.Popen(cmd)


def run_server():
    """Launch the protocol process (RADIUS + TACACS+) AND the web server, then
    supervise both. If either exits, tear the other down and exit non-zero so the
    container's restart policy brings everything back cleanly — no half-up states.

    The protocol servers MUST run in their own process: gunicorn runs multiple
    workers and only one process can bind the RADIUS/TACACS+ ports.
    """
    procs = {}
    procs["aaa"] = _spawn([sys.executable, "-m", "app.services.runner"], "AAA protocols")

    if os.getenv("USE_GUNICORN", "false").lower() == "true":
        try:
            import gunicorn  # noqa: F401
            host = os.getenv("IDP_HOST", "0.0.0.0")
            port = os.getenv("IDP_PORT", "5000")
            workers = os.getenv("GUNICORN_WORKERS", "2")
            procs["web"] = _spawn(
                ["gunicorn", "--bind", f"{host}:{port}", "--workers", workers,
                 "--access-logfile", "-", "run:app"], "gunicorn web")
        except ImportError:
            print("⚠️  gunicorn not installed — using the Flask dev server.")
            procs["web"] = _spawn([sys.executable, "run.py"], "flask web")
    else:
        procs["web"] = _spawn([sys.executable, "run.py"], "flask web")

    def _shutdown(*_):
        for p in procs.values():
            if p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
        sys.exit(1)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while True:
        for name, p in procs.items():
            rc = p.poll()
            if rc is not None:
                print(f"✖  '{name}' exited (rc={rc}); shutting down so the container restarts clean.", flush=True)
                _shutdown()
        time.sleep(2)


def main():
    print("🚀 Starting SAML Identity Provider...")
    generate_certificates()
    run_server()


if __name__ == "__main__":
    main()
