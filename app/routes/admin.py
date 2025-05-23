from flask import (
    Blueprint,
    request,
    redirect,
    url_for,
    render_template,
    flash,
    session,
    current_app,
    jsonify,
)
from functools import wraps
from werkzeug.security import check_password_hash
from flask_wtf.csrf import validate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.utils.models import User, ServiceProvider
from app.utils.user_manager import UserManager
from urllib.parse import urlparse
import uuid
from app import db
from app.utils.logger_main import log

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
limiter = Limiter(key_func=get_remote_address)


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in") or session.get("account_type") != "admin":
            session.clear()
            flash("Admin session expired", "warning")
            return redirect(url_for("admin.login"))
        return f(*args, **kwargs)

    return decorated_function


@admin_bp.after_request
def add_security_headers(response):
    headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    }
    for header, value in headers.items():
        response.headers[header] = value
    return response


@admin_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        try:
            validate_csrf(request.form.get("csrf_token"))
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            config = current_app.config

            if not all([username, password]):
                flash("Please fill in all fields", "danger")
            elif username == config["ADMIN_USERNAME"] and check_password_hash(
                config["ADMIN_PASSWORD_HASH"], password
            ):
                session.clear()
                session["admin_logged_in"] = True
                session["account_type"] = "admin"
                session.permanent = False
                return redirect(url_for("admin.user_management"))
            else:
                flash("Invalid username or password", "danger")

        except CSRFError:
            flash("Invalid CSRF token", "danger")
        except Exception as e:
            log.error(f"Login error: {e}")
            flash("Login failed", "danger")

    return render_template("admin/login.html")


@admin_bp.route("/logout")
@admin_login_required
def logout():
    session.pop("admin_logged_in", None)
    session.pop("account_type", None)
    flash("You have been logged out", "success")
    return redirect(url_for("admin.login"))


@admin_bp.route("/add", methods=["POST"])
@admin_login_required
def add_user():
    try:
        validate_csrf(request.form.get("csrf_token"))

        data = {
            k: request.form.get(k, "").strip()
            for k in [
                "username",
                "password",
                "email",
                "first_name",
                "last_name",
                "groups",
            ]
        }
        if not all(
            [
                data["username"],
                data["password"],
                data["email"],
                data["first_name"],
                data["last_name"],
            ]
        ):
            flash("All fields are required", "danger")
            return redirect(url_for("admin.user_management"))

        groups = [g.strip() for g in data["groups"].split(",") if g.strip()]
        UserManager.add_user(
            username=data["username"],
            password=data["password"],
            email=data["email"].lower(),
            groups=groups,
            first_name=data["first_name"],
            last_name=data["last_name"],
            user_id=str(uuid.uuid4()),
        )

        flash("User added successfully", "success")
    except (ValueError, CSRFError) as e:
        flash(str(e), "danger")
    except Exception as e:
        log.error(f"User add error: {str(e)}", exc_info=True)
        flash("Error adding user", "danger")

    return redirect(url_for("admin.user_management"))


@admin_bp.route("/update_user", methods=["POST"])
@admin_login_required
def update_user():
    try:
        username = request.form.get("username")
        if not username:
            return jsonify({"success": False, "error": "Username is required"}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        # Update allowed fields
        for field in User.get_editable_user_fields():
            if field == "groups":
                raw = request.form.get("groups", "")
                user.groups = [g.strip() for g in raw.split(",") if g.strip()]
            elif field == "password":
                raw_pass = request.form.get("password", "").strip()
                if raw_pass:
                    UserManager.set_password(user, raw_pass)
            else:
                setattr(user, field, request.form.get(field, "").strip())

        db.session.commit()
        return jsonify({"success": True})

    except Exception as e:
        log.error(f"❌ Failed to update user: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": str(e)}),
            500,
        )  # Always return something


@admin_bp.route("/delete/<username>")
@admin_login_required
def delete_user(username):
    try:
        UserManager.delete_user(username)
        flash("User deleted successfully", "success")
    except Exception as e:
        log.error(f"User delete error: {str(e)}", exc_info=True)
        flash("Error deleting user", "danger")
    return redirect(url_for("admin.user_management"))


@admin_bp.route("/users")
@admin_login_required
def user_management():
    users = User.query.all()
    users_list = []
    for u in users:
        users_list.append(
            {
                "username": u.username,
                "email": u.email,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "groups": u.groups,
            }
        )

    fields = User.get_editable_user_fields()
    return render_template(
        "admin/user_management.html", users=users_list, user_fields=fields
    )


@admin_bp.route("/api/user/<username>", methods=["GET"])
@admin_login_required
def get_user_data(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(
        {
            "success": True,
            "user": { 
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "groups": user.groups,
            },
        }
    )


@admin_bp.route("/sp", methods=["GET"])
@admin_login_required
def list_sps():
    sps = ServiceProvider.query.all()

    # Serialize SPs for modal usage
    sp_dicts = []
    for sp in sps:
        sp_dicts.append(
            {
                "id": sp.id,
                "name": sp.name,
                "entity_id": sp.entity_id,
                "acs_url": sp.acs_url,
                "attr_map": sp.attr_map or [],
            }
        )

    fields = [
        col.name for col in User.__table__.columns if col.name not in ["password"]
    ]
    return render_template(
        "admin/sp_list.html", sps=sps, sp_dicts=sp_dicts, user_fields=fields
    )


@admin_bp.route("/sp/new", methods=["GET", "POST"])
@admin_login_required
def create_sp():
    user_fields = [
        col.name for col in User.__table__.columns if col.name != "password_hash"
    ]

    if request.method == "POST":
        name = request.form.get("name")
        entity_id = request.form.get("entity_id")
        existing_sp = ServiceProvider.query.filter_by(entity_id=entity_id).first()
        if existing_sp:
            return jsonify({"error": "An SP with this Entity ID already exists."}), 400

        acs_url = request.form.get("acs_url")
        existing_sp = ServiceProvider.query.filter_by(entity_id=entity_id).first()
        if existing_sp:
            return jsonify({"error": "An SP with this Entity ID already exists."}), 400
        attr_map = []
        index = 0
        while True:
            claim_name = request.form.get(f"claim_name_{index}")
            claim_value = request.form.get(f"claim_value_{index}")
            if not claim_name or not claim_value:
                break
            attr_map.append({"claim": claim_name, "value": claim_value})
            index += 1

        sp = ServiceProvider(
            name=name,
            entity_id=entity_id,
            acs_url=acs_url,
            attr_map=attr_map,
        )
        db.session.add(sp)
        db.session.commit()
        flash("Service Provider added successfully", "success")
        return redirect(url_for("admin.list_sps"))

    return render_template("admin/sp_new.html", user_fields=user_fields)


@admin_bp.route("/sp/delete/<int:sp_id>", methods=["POST"])
@admin_login_required
def delete_sp(sp_id):
    sp = ServiceProvider.query.get_or_404(sp_id)
    db.session.delete(sp)
    db.session.commit()
    flash(f"Deleted Service Provider: {sp.name}", "success")
    return redirect(url_for("admin.list_sps"))


@admin_bp.route("/sp/edit/<int:sp_id>", methods=["GET", "POST"])
@admin_login_required
def edit_sp(sp_id):
    sp = ServiceProvider.query.get_or_404(sp_id)

    if request.method == "POST":
        sp.name = request.form.get("name")
        sp.entity_id = request.form.get("entity_id")
        sp.acs_url = request.form.get("acs_url")

        attr_map = []
        index = 0
        while True:
            claim_name = request.form.get(f"claim_name_{index}")
            claim_value = request.form.get(f"claim_value_{index}")
            if not claim_name or not claim_value:
                break
            attr_map.append({"claim": claim_name, "value": claim_value})
            index += 1

        sp.attr_map = attr_map
        db.session.commit()
        flash("Service Provider updated successfully.", "success")
        return redirect(url_for("admin.list_sps"))

    user_fields = [
        col.name for col in User.__table__.columns if col.name != "password_hash"
    ]
    return render_template("admin/sp_edit.html", sp=sp, user_fields=user_fields)


@admin_bp.route("/api/sp/<int:sp_id>", methods=["GET"])
@admin_login_required
def get_sp_data(sp_id):
    sp = ServiceProvider.query.get(sp_id)
    if not sp:
        return jsonify({"error": "Service Provider not found"}), 404

    return jsonify(
        {
            "success": True,
            "sp": {
                "id": sp.id,
                "name": sp.name,
                "entity_id": sp.entity_id,
                "acs_url": sp.acs_url,
                "attr_map": sp.attr_map or [],
            },
        }
    )
