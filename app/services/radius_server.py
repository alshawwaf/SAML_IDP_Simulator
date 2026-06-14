"""RADIUS authentication + accounting server (pyrad packet over raw UDP).

Authenticates against the shared `User` directory and returns the user's group
names as Class attributes. MFA users get an Access-Challenge for a one-time
passcode (AaaUserAuth.otp, else the demo default). Events go to AaaLog.

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
from app.utils.models_aaa import AaaUserAuth, log_event

_DICT = Dictionary(os.path.join(os.path.dirname(__file__), "radius_dictionary"))
_challenges: dict[str, str] = {}
_lock = threading.Lock()


def _text(v):
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


def _secret() -> bytes:
    return config_manager.RADIUS_SECRET.encode()


def _accept(reply, user):
    reply.code = packet.AccessAccept
    for group in (user.group_names or []):
        reply.AddAttribute("Class", group.encode())
    reply.AddAttribute("Reply-Message", "Authenticated by PoV Integration Toolkit")


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

    # Second leg of an MFA exchange: the password field now carries the OTP.
    if state:
        with _lock:
            pending = _challenges.pop(state, None)
        user = User.query.filter_by(username=username).first() if username else None
        aaa = AaaUserAuth.query.filter_by(user_id=user.id).first() if user else None
        expected = aaa.otp if (aaa and aaa.otp) else config_manager.AAA_DEFAULT_OTP
        if pending == username and password and password == expected:
            _accept(reply, user)
            log_event("radius", "auth", username, nas, "accept", "OTP verified")
        else:
            reply.code = packet.AccessReject
            reply.AddAttribute("Reply-Message", "Invalid one-time passcode")
            log_event("radius", "auth", username, nas, "reject", "bad OTP")
        return reply

    user = User.query.filter_by(username=username).first()
    if not user or not user.active or not user.check_password(password):
        reply.code = packet.AccessReject
        reply.AddAttribute("Reply-Message", "Invalid credentials")
        log_event("radius", "auth", username, nas, "reject", "bad credentials")
        return reply

    aaa = AaaUserAuth.query.filter_by(user_id=user.id).first()
    if aaa and aaa.mfa:
        token = os.urandom(8)
        with _lock:
            _challenges[binascii.hexlify(token).decode()] = username
        reply.code = packet.AccessChallenge
        reply.AddAttribute("Reply-Message", "Enter your one-time passcode")
        reply.AddAttribute("State", token)
        log_event("radius", "auth", username, nas, "challenge", "MFA requested")
    else:
        _accept(reply, user)
        log_event("radius", "auth", username, nas, "accept", "password OK")
    return reply


_ACCT_STATUS = {1: "start", 2: "stop", 3: "interim"}


def handle_acct(data, addr):
    pkt = packet.AcctPacket(packet=data, dict=_DICT, secret=_secret())
    username = _text(pkt["User-Name"][0]) if "User-Name" in pkt else ""
    status = pkt["Acct-Status-Type"][0] if "Acct-Status-Type" in pkt else 0
    log_event("radius", "acct", username, addr[0], _ACCT_STATUS.get(status, str(status)), "accounting")
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
    """Spawn the RADIUS auth + accounting listener threads."""
    threading.Thread(target=_serve, args=(app, config_manager.RADIUS_AUTH_PORT, handle_auth, "auth"),
                     daemon=True, name="radius-auth").start()
    threading.Thread(target=_serve, args=(app, config_manager.RADIUS_ACCT_PORT, handle_acct, "acct"),
                     daemon=True, name="radius-acct").start()
