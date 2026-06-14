"""A minimal TACACS+ server (RFC 8907) for Check Point Gaia / device-admin AAA
demos. No mature Python TACACS+ *server* library exists, so this implements the
wire protocol directly:

  * 12-byte header + MD5 body de/obfuscation (the TACACS+ "encryption")
  * Authentication: ASCII login (Username/Password prompts) and PAP
  * Authorization: permissive PASS_ADD returning priv-lvl=15 so a demo admin
    actually gets an admin shell on Gaia
  * Accounting: SUCCESS + logged

Authenticates against the shared `User` directory. Runs in the protocol process
(app.services.runner), binding an unprivileged port (default 4949) that compose
maps to host 49, so the container stays non-root.
"""
import hashlib
import socket
import struct
import threading

from app.utils.config_manager import config_manager
from app.utils.models import db, User
from app.utils.models_aaa import log_event

# Packet types
TAC_AUTHEN, TAC_AUTHOR, TAC_ACCT = 0x01, 0x02, 0x03
FLAG_UNENCRYPTED = 0x01
# Authentication status / type (RFC 8907 §5.4.2.1 — contiguous 1..7)
ST_PASS, ST_FAIL, ST_GETDATA, ST_GETUSER, ST_GETPASS, ST_RESTART, ST_ERROR = 1, 2, 3, 4, 5, 6, 7
AT_ASCII, AT_PAP, AT_CHAP = 1, 2, 3
REPLY_NOECHO = 0x01


def _key() -> bytes:
    return config_manager.TACACS_SECRET.encode()


def _crypt(session_id: int, key: bytes, version: int, seq_no: int, body: bytes) -> bytes:
    """De/obfuscate a TACACS+ body (XOR with an MD5-chained pad; symmetric)."""
    if not key or not body:
        return body
    sid = struct.pack("!I", session_id)
    ver = bytes([version])
    seq = bytes([seq_no])
    pad, prev = b"", b""
    while len(pad) < len(body):
        prev = hashlib.md5(sid + key + ver + seq + prev).digest()
        pad += prev
    return bytes(a ^ b for a, b in zip(body, pad[: len(body)]))


def _recvn(conn, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def _read_packet(conn, key):
    """Read one TACACS+ packet; return (version, type, seq, flags, session_id, body)
    with the body already deobfuscated, or None on a closed/short connection."""
    hdr = _recvn(conn, 12)
    if len(hdr) < 12:
        return None
    version, type_, seq, flags = hdr[0], hdr[1], hdr[2], hdr[3]
    session_id = struct.unpack("!I", hdr[4:8])[0]
    length = struct.unpack("!I", hdr[8:12])[0]
    body = _recvn(conn, length)
    if not (flags & FLAG_UNENCRYPTED):
        body = _crypt(session_id, key, version, seq, body)
    return version, type_, seq, flags, session_id, body


def _send(conn, version, type_, seq, flags, session_id, key, body):
    out = body if (flags & FLAG_UNENCRYPTED) else _crypt(session_id, key, version, seq, body)
    hdr = bytes([version, type_, seq, flags]) + struct.pack("!I", session_id) + struct.pack("!I", len(out))
    conn.sendall(hdr + out)


# ---- body codecs ---------------------------------------------------------
def _parse_authen_start(b):
    action, priv, atype, service = b[0], b[1], b[2], b[3]
    ul, pl, ral, dl = b[4], b[5], b[6], b[7]
    o = 8
    user = b[o:o + ul]; o += ul
    o += pl  # port
    o += ral  # rem_addr
    data = b[o:o + dl]
    return atype, user.decode(errors="replace"), data


def _parse_authen_continue(b):
    uml = struct.unpack("!H", b[0:2])[0]
    dl = struct.unpack("!H", b[2:4])[0]
    o = 5  # skip flags byte
    user_msg = b[o:o + uml]; o += uml
    data = b[o:o + dl]
    return user_msg.decode(errors="replace"), data


def _authen_reply_body(status, server_msg="", noecho=False, data=b""):
    sm = server_msg.encode()
    flags = REPLY_NOECHO if noecho else 0
    return bytes([status, flags]) + struct.pack("!H", len(sm)) + struct.pack("!H", len(data)) + sm + data


def _author_reply_body(args):
    arg_bytes = [a.encode() for a in args]
    body = bytes([1, len(arg_bytes)])            # status=PASS_ADD, arg_cnt
    body += struct.pack("!H", 0) + struct.pack("!H", 0)  # server_msg_len, data_len
    body += bytes(len(a) for a in arg_bytes)     # per-arg lengths
    for a in arg_bytes:
        body += a
    return body


def _acct_reply_body():
    return struct.pack("!H", 0) + struct.pack("!H", 0) + bytes([1])  # status=SUCCESS


def _parse_author_user(b):
    ul, arg_cnt = b[4], b[7]
    return b[8 + arg_cnt: 8 + arg_cnt + ul].decode(errors="replace")


# ---- DB-backed verification ----------------------------------------------
def _verify(app, username, password) -> bool:
    with app.app_context():
        try:
            user = User.query.filter_by(username=username).first()
            return bool(user and user.active and user.check_password(password))
        finally:
            db.session.remove()


def _log(app, kind, username, nas, result, detail=""):
    with app.app_context():
        log_event("tacacs", kind, username, nas, result, detail)
        db.session.remove()


# ---- exchange handlers ---------------------------------------------------
def _handle_authen(conn, app, version, sid, seq, flags, body, nas):
    key = _key()
    atype, user, data = _parse_authen_start(body)

    if atype == AT_PAP:
        ok = _verify(app, user, data.decode(errors="replace"))
        _send(conn, version, TAC_AUTHEN, seq + 1, flags, sid, key,
              _authen_reply_body(ST_PASS if ok else ST_FAIL))
        _log(app, "auth", user, nas, "accept" if ok else "reject", "pap")
        return

    if atype == AT_ASCII:
        if not user:
            _send(conn, version, TAC_AUTHEN, seq + 1, flags, sid, key,
                  _authen_reply_body(ST_GETUSER, "Username: "))
            pkt = _read_packet(conn, key)
            if not pkt:
                return
            seq = pkt[2]
            user, _ = _parse_authen_continue(pkt[5])
        _send(conn, version, TAC_AUTHEN, seq + 1, flags, sid, key,
              _authen_reply_body(ST_GETPASS, "Password: ", noecho=True))
        pkt = _read_packet(conn, key)
        if not pkt:
            return
        seq = pkt[2]
        password, _ = _parse_authen_continue(pkt[5])
        ok = _verify(app, user, password)
        _send(conn, version, TAC_AUTHEN, seq + 1, flags, sid, key,
              _authen_reply_body(ST_PASS if ok else ST_FAIL))
        _log(app, "auth", user, nas, "accept" if ok else "reject", "ascii")
        return

    # CHAP / others not supported in this simulator.
    _send(conn, version, TAC_AUTHEN, seq + 1, flags, sid, key,
          _authen_reply_body(ST_ERROR, "Unsupported authen type"))
    _log(app, "auth", user, nas, "error", f"unsupported authen_type {atype}")


def _handle_author(conn, app, version, sid, seq, flags, body, nas):
    user = _parse_author_user(body)
    # Permissive demo authorization: grant admin so Gaia assigns the admin role.
    _send(conn, version, TAC_AUTHOR, seq + 1, flags, sid, _key(),
          _author_reply_body(["priv-lvl=15", "shell:roles=adminRole"]))
    _log(app, "author", user, nas, "accept", "priv-lvl=15")


def _handle_acct(conn, app, version, sid, seq, flags, body, nas):
    _send(conn, version, TAC_ACCT, seq + 1, flags, sid, _key(), _acct_reply_body())
    _log(app, "acct", "", nas, "start", "accounting")


def _handle_connection(conn, addr, app):
    nas = addr[0]
    try:
        pkt = _read_packet(conn, _key())
        if not pkt:
            return
        version, type_, seq, flags, sid, body = pkt
        if type_ == TAC_AUTHEN:
            _handle_authen(conn, app, version, sid, seq, flags, body, nas)
        elif type_ == TAC_AUTHOR:
            _handle_author(conn, app, version, sid, seq, flags, body, nas)
        elif type_ == TAC_ACCT:
            _handle_acct(conn, app, version, sid, seq, flags, body, nas)
    except Exception as exc:  # never let one bad client kill the server
        try:
            _log(app, "auth", "", nas, "error", str(exc))
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _accept_loop(app):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((config_manager.AAA_BIND, config_manager.TACACS_PORT))
    sock.listen(50)
    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            continue
        threading.Thread(target=_handle_connection, args=(conn, addr, app), daemon=True).start()


def start(app):
    threading.Thread(target=_accept_loop, args=(app,), daemon=True, name="tacacs").start()
