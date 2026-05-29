"""Admin UI for SCIM outbound targets, inbound tokens, and push-log audit.

Lives under /admin/scim/* and shares the existing admin session + CSRF
machinery from the main admin blueprint. The SCIM **server** endpoints under
/scim/v2 are bearer-token-authed and CSRF-exempt — separate concern.
"""
from functools import wraps

from flask import (
    Blueprint, abort, flash, jsonify, redirect, render_template, request,
    session, url_for,
)

from app.routes.scim.bootstrap import clear_bootstrap_token, read_bootstrap_token
from app.routes.scim.client import ScimClient, ScimClientError
from app.utils.crypto import (
    encrypt_token, generate_inbound_token, hash_inbound_token,
)
from app.utils.models import db, User
from app.utils.models_scim import (
    ScimGroup, ScimInboundToken, ScimPushLog, ScimTarget,
)


scim_admin_bp = Blueprint("scim_admin", __name__, url_prefix="/admin/scim")


def _admin_required(f):
    """Same gate the main admin blueprint uses."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.login"))
        return f(*args, **kwargs)
    return wrapped


# --- Dashboard ---------------------------------------------------------------

@scim_admin_bp.route("/")
@_admin_required
def dashboard():
    targets = ScimTarget.query.order_by(ScimTarget.created_at.desc()).all()
    inbound = ScimInboundToken.query.order_by(ScimInboundToken.created_at.desc()).all()
    recent_log = ScimPushLog.query.order_by(ScimPushLog.id.desc()).limit(10).all()
    return render_template(
        "admin/scim/dashboard.html",
        targets=targets,
        inbound_tokens=inbound,
        recent_log=recent_log,
        bootstrap_token=read_bootstrap_token(),
    )


@scim_admin_bp.route("/bootstrap-token/ack", methods=["POST"])
@_admin_required
def acknowledge_bootstrap_token():
    """Operator confirmed they copied the auto-generated token — delete the file."""
    if clear_bootstrap_token():
        flash("Bootstrap token file deleted. Manage tokens at /admin/scim/inbound-tokens.", "success")
    else:
        flash("Bootstrap token file already absent.", "success")
    return redirect(url_for("scim_admin.dashboard"))


# --- Outbound targets --------------------------------------------------------

@scim_admin_bp.route("/targets")
@_admin_required
def list_targets():
    targets = ScimTarget.query.order_by(ScimTarget.created_at.desc()).all()
    users = User.query.order_by(User.username).all()
    return render_template("admin/scim/targets.html", targets=targets, users=users)


@scim_admin_bp.route("/targets/new", methods=["GET", "POST"])
@_admin_required
def new_target():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        base_url = (request.form.get("base_url") or "").strip()
        token = (request.form.get("bearer_token") or "").strip()
        if not name or not base_url or not token:
            flash("Name, base URL, and bearer token are all required.", "error")
            return redirect(url_for("scim_admin.new_target"))
        try:
            encrypted = encrypt_token(token)
        except RuntimeError as e:
            flash(f"Cannot encrypt token: {e}", "error")
            return redirect(url_for("scim_admin.new_target"))
        target = ScimTarget(
            name=name,
            base_url=base_url.rstrip("/"),
            bearer_token_encrypted=encrypted,
            enabled=True,
        )
        db.session.add(target)
        db.session.commit()
        flash(f"SCIM target {name!r} created.", "success")
        return redirect(url_for("scim_admin.list_targets"))
    return render_template("admin/scim/target_edit.html", target=None)


@scim_admin_bp.route("/targets/<int:target_id>/edit", methods=["GET", "POST"])
@_admin_required
def edit_target(target_id):
    target = ScimTarget.query.get_or_404(target_id)
    if request.method == "POST":
        target.name = (request.form.get("name") or target.name).strip()
        new_url = (request.form.get("base_url") or "").strip()
        if new_url:
            target.base_url = new_url.rstrip("/")
        target.enabled = bool(request.form.get("enabled"))
        token = (request.form.get("bearer_token") or "").strip()
        if token:
            try:
                target.bearer_token_encrypted = encrypt_token(token)
            except RuntimeError as e:
                flash(f"Cannot encrypt token: {e}", "error")
                return redirect(url_for("scim_admin.edit_target", target_id=target.id))
        db.session.commit()
        flash(f"SCIM target {target.name!r} updated.", "success")
        return redirect(url_for("scim_admin.list_targets"))
    return render_template("admin/scim/target_edit.html", target=target)


@scim_admin_bp.route("/targets/<int:target_id>/delete", methods=["POST"])
@_admin_required
def delete_target(target_id):
    target = ScimTarget.query.get_or_404(target_id)
    name = target.name
    db.session.delete(target)
    db.session.commit()
    flash(f"SCIM target {name!r} deleted.", "success")
    return redirect(url_for("scim_admin.list_targets"))


@scim_admin_bp.route("/targets/<int:target_id>/test", methods=["POST"])
@_admin_required
def test_target(target_id):
    """AJAX endpoint — performs a discovery GET against the target."""
    target = ScimTarget.query.get_or_404(target_id)
    try:
        with ScimClient(target) as c:
            resp = c.test_connection()
        return jsonify({
            "ok": 200 <= resp.status_code < 300,
            "status_code": resp.status_code,
            "snippet": resp.text[:500],
        })
    except (ScimClientError, RuntimeError) as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@scim_admin_bp.route("/targets/<int:target_id>/sync", methods=["POST"])
@_admin_required
def sync_all_users(target_id):
    target = ScimTarget.query.get_or_404(target_id)
    user_q = User.query.order_by(User.id)
    created = updated = errored = 0
    try:
        with ScimClient(target) as c:
            for u in user_q.all():
                try:
                    action, resp = c.upsert_user(u)
                    if action == "created" and 200 <= resp.status_code < 300:
                        created += 1
                    elif action == "updated" and 200 <= resp.status_code < 300:
                        updated += 1
                    else:
                        errored += 1
                except ScimClientError:
                    errored += 1
    except RuntimeError as e:
        flash(f"SCIM client error: {e}", "error")
        return redirect(url_for("scim_admin.list_targets"))

    flash(
        f"Sync to {target.name!r}: {created} created, {updated} updated, {errored} errored.",
        "success" if errored == 0 else "error",
    )
    return redirect(url_for("scim_admin.list_targets"))


@scim_admin_bp.route("/targets/<int:target_id>/sync/<int:user_id>", methods=["POST"])
@_admin_required
def sync_one_user(target_id, user_id):
    target = ScimTarget.query.get_or_404(target_id)
    user = User.query.get_or_404(user_id)
    try:
        with ScimClient(target) as c:
            action, resp = c.upsert_user(user)
    except (ScimClientError, RuntimeError) as e:
        flash(f"Failed to sync {user.username!r}: {e}", "error")
        return redirect(url_for("scim_admin.list_targets"))

    ok = 200 <= resp.status_code < 300
    flash(
        f"{user.username!r} → {target.name!r}: {action} ({resp.status_code}).",
        "success" if ok else "error",
    )
    return redirect(url_for("scim_admin.list_targets"))


# --- Inbound bearer tokens ---------------------------------------------------

@scim_admin_bp.route("/inbound-tokens")
@_admin_required
def list_inbound_tokens():
    tokens = ScimInboundToken.query.order_by(ScimInboundToken.created_at.desc()).all()
    # Fresh token may be flashed-once via session — see new_inbound_token
    fresh_token = session.pop("_scim_fresh_token", None)
    fresh_token_name = session.pop("_scim_fresh_token_name", None)
    return render_template(
        "admin/scim/inbound_tokens.html",
        tokens=tokens,
        fresh_token=fresh_token,
        fresh_token_name=fresh_token_name,
        bootstrap_token=read_bootstrap_token(),
    )


@scim_admin_bp.route("/inbound-tokens/new", methods=["POST"])
@_admin_required
def new_inbound_token():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Token name is required.", "error")
        return redirect(url_for("scim_admin.list_inbound_tokens"))

    raw_token = generate_inbound_token()
    db.session.add(ScimInboundToken(
        name=name,
        token_hash=hash_inbound_token(raw_token),
        enabled=True,
    ))
    db.session.commit()
    # Surface the raw token ONCE via session — same flow Harmony itself uses.
    session["_scim_fresh_token"] = raw_token
    session["_scim_fresh_token_name"] = name
    flash(f"Inbound token {name!r} created. Copy the value below — it won't be shown again.", "success")
    return redirect(url_for("scim_admin.list_inbound_tokens"))


@scim_admin_bp.route("/inbound-tokens/<int:token_id>/toggle", methods=["POST"])
@_admin_required
def toggle_inbound_token(token_id):
    tok = ScimInboundToken.query.get_or_404(token_id)
    tok.enabled = not tok.enabled
    db.session.commit()
    flash(f"Token {tok.name!r} {'enabled' if tok.enabled else 'disabled'}.", "success")
    return redirect(url_for("scim_admin.list_inbound_tokens"))


@scim_admin_bp.route("/inbound-tokens/<int:token_id>/delete", methods=["POST"])
@_admin_required
def delete_inbound_token(token_id):
    tok = ScimInboundToken.query.get_or_404(token_id)
    name = tok.name
    db.session.delete(tok)
    db.session.commit()
    flash(f"Token {name!r} deleted.", "success")
    return redirect(url_for("scim_admin.list_inbound_tokens"))


# --- Push log ----------------------------------------------------------------

@scim_admin_bp.route("/log")
@_admin_required
def push_log():
    """Paginated SCIM push audit log. Filterable by target and operation."""
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    target_id = request.args.get("target_id", type=int)
    operation = request.args.get("operation")
    status_filter = request.args.get("status")  # "ok" | "error" | None

    q = ScimPushLog.query.order_by(ScimPushLog.id.desc())
    if target_id:
        q = q.filter_by(target_id=target_id)
    if operation:
        q = q.filter_by(operation=operation)
    if status_filter == "ok":
        q = q.filter(ScimPushLog.status_code >= 200, ScimPushLog.status_code < 400)
    elif status_filter == "error":
        q = q.filter((ScimPushLog.status_code >= 400) | (ScimPushLog.error.isnot(None)))

    total = q.count()
    entries = q.offset((page - 1) * per_page).limit(per_page).all()
    targets = ScimTarget.query.order_by(ScimTarget.name).all()

    return render_template(
        "admin/scim/push_log.html",
        entries=entries,
        total=total,
        page=page,
        per_page=per_page,
        targets=targets,
        filter_target_id=target_id,
        filter_operation=operation,
        filter_status=status_filter,
    )


@scim_admin_bp.route("/log/<int:entry_id>")
@_admin_required
def push_log_detail(entry_id):
    entry = ScimPushLog.query.get_or_404(entry_id)
    return render_template("admin/scim/push_log_detail.html", entry=entry)
