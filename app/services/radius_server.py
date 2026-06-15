"""RADIUS authentication + accounting server (pyrad packet over raw UDP).

Authenticates against the shared `User` directory and returns the user's group
names as Class attributes. MFA users get an Access-Challenge for a one-time
passcode. Connection settings (shared secret, ports, default OTP) come from
`get_setting` (portal-editable, persisted) — secret/OTP are read live per
request; ports are bound at startup.

Runs inside the protocol process (app.services.runner), NOT the gunicorn web
workers — only one process can bind a UDP port. Each server thread holds one
app context and resets the session after every request.
"""
import binascii
import os
import socket
import threading

from pyrad import packet
from pyrad.dictionary import Dictionary

from app.utils.config_manager import config_manager
from app.utils.models import db, User
from app.utils.models_aaa import (
    AaaUserAuth, gaia_radius_role, get_setting, log_event, verify_totp,
)

_DICT = Dictionary(os.path.join(os.path.dirname(__file__), "radius_dictionary"))
_challenges: dict[str, str] = {}
_lock = threading.Lock()


def _text(v):
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _secret() -> bytes:
    return get_setting("radius_secret").encode()


def _accept(reply, user):
    reply.code = packet.AccessAccept
    for group in (user.group_names or []):
        reply.AddAttribute("Class", group.encode())
    # Check Point Gaia role-based administration (vendor 2620). Gaia reads these
    # VSAs to assign the admin's role; non-Gaia NAS ignore unknown VSAs, so it's
    # always safe to send them. Role is decided by the user's directory groups.
    role, superuser = gaia_radius_role(user)
    reply.AddAttribute("CP-Gaia-User-Role", role)
    reply.AddAttribute("CP-Gaia-SuperUser-Access", superuser)
    reply.AddAttribute("Reply-Message", "Authenticated by the Identity & Access simulator")


def _req_meta(pkt, addr):
    """Pull the interesting attributes out of a RADIUS request for the log modal."""
    m = {"src": f"{addr[0]}:{addr[1]}", "radius_id": pkt.id}
    for attr in ("NAS-IP-Address", "NAS-Identifier", "NAS-Port", "NAS-Port-Type",
                 "Service-Type", "Calling-Station-Id", "Called-Station-Id",
                 "Acct-Session-Id"):
        try:
            if attr in pkt:
                v = pkt[attr][0]
                if isinstance(v, (bytes, bytearray)):
                    v = v.decode("utf-8", "replace")
                m[attr] = str(v)
        except Exception:
            pass
    return m


def handle_auth(data, addr):
    pkt = packet.AuthPacket(packet=data, dict=_DICT, secret=_secret())
    nas = addr[0]
    username = _text(pkt["User-Name"][0]) if "User-Name" in pkt else ""
    try:
        password = _text(pkt.PwDecrypt(pkt["User-Password"][0])) if "User-Password" in pkt else ""
    except Exception:
        password = ""
    state = binascii.hexlify(pkt["State"][0]).decode() if "State" in pkt else None
    reply = pkt.CreateReply()
    meta = _req_meta(pkt, addr)

    # Second leg of an MFA exchange: the password field carries the TOTP code.
    if state:
        with _lock:
            pending = _challenges.pop(state, None)
        user = User.query.filter_by(username=username).first() if username else None
        aaa = AaaUserAuth.query.filter_by(user_id=user.id).first() if user else None
        if pending == username and verify_totp(aaa, password):
            _accept(reply, user)
            role, su = gaia_radius_role(user)
            log_event("radius", "auth", username, nas, "accept", "TOTP verified",
                      meta={**meta, "reply": "Access-Accept", "auth_via": "TOTP (second factor)",
                            "groups": list(user.group_names or []),
                            "CP-Gaia-User-Role": role, "CP-Gaia-SuperUser-Access": su})
        else:
            reply.code = packet.AccessReject
            reply.AddAttribute("Reply-Message", "Invalid authenticator code")
            log_event("radius", "auth", username, nas, "reject", "bad TOTP",
                      meta={**meta, "reply": "Access-Reject", "auth_via": "TOTP (second factor)",
                            "reason": "invalid authenticator code"})
        return reply

    user = User.query.filter_by(username=username).first()
    if not user or not user.active or not user.check_password(password):
        reason = ("unknown user" if not user
                  else "inactive user" if not user.active else "wrong password")
        reply.code = packet.AccessReject
        reply.AddAttribute("Reply-Message", "Invalid credentials")
        log_event("radius", "auth", username, nas, "reject", "bad credentials",
                  meta={**meta, "reply": "Access-Reject", "reason": reason})
        return reply

    aaa = AaaUserAuth.query.filter_by(user_id=user.id).first()
    if aaa and aaa.mfa:
        token = os.urandom(8)
        with _lock:
            _challenges[binascii.hexlify(token).decode()] = username
        reply.code = packet.AccessChallenge
        reply.AddAttribute("Reply-Message", "Enter the code from your authenticator app")
        reply.AddAttribute("State", token)
        log_event("radius", "auth", username, nas, "challenge", "MFA requested",
                  meta={**meta, "reply": "Access-Challenge", "mfa": "TOTP code requested",
                        "groups": list(user.group_names or [])})
    else:
        _accept(reply, user)
        role, su = gaia_radius_role(user)
        log_event("radius", "auth", username, nas, "accept", "password OK",
                  meta={**meta, "reply": "Access-Accept", "auth_via": "password",
                        "groups": list(user.group_names or []),
                        "CP-Gaia-User-Role": role, "CP-Gaia-SuperUser-Access": su})
    return reply


_ACCT_STATUS = {1: "start", 2: "stop", 3: "interim"}


def handle_acct(data, addr):
    pkt = packet.AcctPacket(packet=data, dict=_DICT, secret=_secret())
    username = _text(pkt["User-Name"][0]) if "User-Name" in pkt else ""
    status = pkt["Acct-Status-Type"][0] if "Acct-Status-Type" in pkt else 0
    status_name = _ACCT_STATUS.get(status, str(status))
    log_event("radius", "acct", username, addr[0], status_name, "accounting",
              meta={**_req_meta(pkt, addr), "reply": "Accounting-Response",
                    "Acct-Status-Type": status_name})
    reply = pkt.CreateReply()
    reply.code = packet.AccountingResponse
    return reply


def _serve(app, port, handler, label):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((config_manager.AAA_BIND, port))
    with app.app_context():
        while True:
            try:
                data, addr = sock.recvfrom(8192)
            except OSError:
                continue
            try:
                reply = handler(data, addr)
                sock.sendto(reply.ReplyPacket(), addr)
            except Exception as exc:  # a malformed packet must never kill the loop
                log_event("radius", label, "", addr[0] if addr else "", "error", str(exc))
            finally:
                db.session.remove()


def start(app):
    """Bind the RADIUS auth + accounting listeners (ports read at startup)."""
    with app.app_context():
        auth_port = int(get_setting("radius_auth_port"))
        acct_port = int(get_setting("radius_acct_port"))
    threading.Thread(target=_serve, args=(app, auth_port, handle_auth, "auth"),
                     daemon=True, name="radius-auth").start()
    threading.Thread(target=_serve, args=(app, acct_port, handle_acct, "acct"),
                     daemon=True, name="radius-acct").start()
    return auth_port, acct_port
