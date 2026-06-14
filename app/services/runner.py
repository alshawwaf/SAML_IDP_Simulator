"""Protocol process entrypoint — hosts the RADIUS + TACACS+ servers.

Run as `python -m app.services.runner`. The container's entrypoint launches this
alongside gunicorn. It builds the app with init_db=False (so only the web process
migrates/seeds — no init race), waits for the web process to create the schema,
then starts the listeners. Binding here, in one process, avoids the
"address already in use" you'd get if each gunicorn worker tried to bind.
"""
import time

from sqlalchemy import inspect

from app import create_app
from app.utils.models import db
from app.services import radius_server, tacacs_server


def _wait_for_schema(app, timeout=180):
    """Block until the web process has created the tables we read/write."""
    deadline = time.time() + timeout
    while True:
        with app.app_context():
            try:
                insp = inspect(db.engine)
                if insp.has_table("user") and insp.has_table("aaa_log"):
                    return True
            except Exception:
                pass
        if time.time() > deadline:
            return False
        time.sleep(2)


def main():
    app = create_app(init_db=False)
    if not _wait_for_schema(app):
        print("AAA runner: schema not ready after wait — starting anyway.", flush=True)
    rad_auth, rad_acct = radius_server.start(app)
    tac_port = tacacs_server.start(app)
    print(
        f"AAA protocols up — RADIUS auth :{rad_auth}/udp acct :{rad_acct}/udp ; "
        f"TACACS+ :{tac_port}/tcp",
        flush=True,
    )
    while True:  # daemon server threads do the work
        time.sleep(3600)


if __name__ == "__main__":
    main()
