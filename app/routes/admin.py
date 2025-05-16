from flask import (
    Blueprint,
    request,
    redirect,
    url_for,
    render_template,
    flash,
    session,
    current_app,
)
from functools import wraps
from werkzeug.security import check_password_hash
from flask_wtf.csrf import validate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.utils.models import User
from app.utils.config_manager import IdPConfigManager
from app.utils.user_manager import UserManager
from app.utils.saml import IdPHandler
from app.utils.path_config import paths
from urllib.parse import urlparse
from pathlib import Path
import os
from lxml import etree

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Initialize rate limiter
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
    """Add security headers to all admin routes"""
    headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",  # Allow inline scripts
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    }
    for header, value in headers.items():
        response.headers[header] = value
    return response


@admin_bp.route("/")
@admin_login_required
def user_list():
    users = User.query.all()
    return render_template("admin/users.html", users=users)


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
                # Clear any existing sessions
                session.clear()
                # Set ADMIN-specific session
                session["admin_logged_in"] = True
                session["account_type"] = "admin"
                session.permanent = False
                return redirect(url_for("admin.user_list"))
            else:
                flash("Invalid username or password", "danger")
            return render_template("admin/login.html")
        except CSRFError:
            flash("Invalid CSRF token", "danger")
            return render_template("admin/login.html")
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

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip().lower()
        groups = request.form.get("groups", "").strip()

        if not all([username, password, email]):
            flash("All fields are required", "danger")
            return redirect(url_for("admin.user_list"))

        UserManager.add_user(username, password, email=email, groups=groups)
        flash("User added successfully", "success")

    except ValueError as e:
        flash(str(e), "danger")
    except CSRFError:
        flash("Invalid CSRF token", "danger")
    except Exception as e:
        current_app.logger.error(f"User add error: {str(e)}")
        flash("Error adding user", "danger")

    return redirect(url_for("admin.user_list"))


@admin_bp.route("/edit-user/<username>", methods=["GET", "POST"])
@admin_login_required
def edit_user(username):
    user = User.query.filter_by(username=username).first_or_404()

    if request.method == "POST":
        try:
            validate_csrf(request.form.get("csrf_token"))

            # Update user details
            new_email = request.form.get("email", "").strip()
            new_groups = request.form.get("groups", "").strip()
            UserManager.update_user(username, email=new_email, groups=new_groups)

            flash("User updated successfully", "success")
            return redirect(url_for("admin.user_list"))

        except Exception as e:
            flash(str(e), "danger")

    return render_template("admin/edit_user.html", user=user)


@admin_bp.route("/delete/<username>")
@admin_login_required
def delete_user(username):
    try:
        UserManager.delete_user(username)
        flash("User deleted successfully", "success")
    except Exception as e:
        current_app.logger.error(f"User delete error: {str(e)}")
        flash("Error deleting user", "danger")
    return redirect(url_for("admin.user_list"))


@admin_bp.route("/idp-config", methods=["GET", "POST"])
@admin_login_required
def idp_config():
    if request.method == "POST":
        try:
            current_config = IdPConfigManager.get_config() or {}

            # Get SP data from form (corrected field names)
            sp_entity_id = request.form.get("sp_entity_id", "").strip()
            sp_acs_url = request.form.get("sp_acs_url", "").strip()

            new_config = {
                "entity_id": request.form.get("entity_id", "").strip(),
                "sso_service_url": request.form.get("sso_service_url", "").strip(),
                "signing_cert_path": request.form.get("cert_path", "").strip()
                or current_config.get(
                    "signing_cert_path", str(paths.cert_dir / "idp-cert.pem")
                ),
                "signing_key_path": request.form.get("key_path", "").strip()
                or current_config.get(
                    "signing_key_path", str(paths.cert_dir / "idp-key.pem")
                ),
                "trusted_sp": [],
            }

            # Add SP only if fields are filled
            if sp_entity_id and sp_acs_url:
                new_config["trusted_sp"].append(
                    {"entity_id": sp_entity_id, "acs_url": sp_acs_url}
                )

            # Validate SP entries
            for sp in new_config["trusted_sp"]:
                if not valid_url(sp["entity_id"]) or not valid_url(sp["acs_url"]):
                    flash("Invalid SP URL format", "danger")
                    return redirect(url_for("admin.idp_config"))

            # Validate required fields
            if not all([new_config["entity_id"], new_config["sso_service_url"]]):
                flash("Entity ID and SSO URL are required", "danger")
                return redirect(url_for("admin.idp_config"))

            # Generate and save config
            idp_handler = IdPHandler()
            config_xml = idp_handler.generate_config_xml(new_config)

            config_path = paths.config_dir / "idps" / "idp-config.xml"
            config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(config_path, "w") as f:
                f.write(config_xml)

            flash("Configuration updated successfully", "success")
            return redirect(url_for("admin.idp_config"))

        except Exception as e:
            current_app.logger.error(f"Config error: {str(e)}")
            flash(f"Configuration update failed: {str(e)}", "danger")
            return redirect(url_for("admin.idp_config"))

    if request.method == "GET":
        try:
            config_path = paths.config_dir / "idps" / "idp-config.xml"
            config_data = {}

            if config_path.exists():
                tree = etree.parse(str(config_path))
                root = tree.getroot()

                config_data = {
                    "entity_id": root.get("entityID"),
                    "sso_service_url": root.find(".//{*}SingleSignOnService").get(
                        "Location"
                    ),
                    "cert_path": paths.cert_dir / "idp-cert.pem",
                    "key_path": paths.cert_dir / "idp-key.pem",
                    "trusted_sp": [
                        {
                            "entity_id": sp.find(".//{*}EntityID").text,
                            "acs_url": sp.find(".//{*}AssertionConsumerService").get(
                                "Location"
                            ),
                        }
                        for sp in root.findall(".//{*}SPSSODescriptor")
                    ],
                }

            return render_template("admin/idp_config.html", config=config_data)

        except Exception as e:
            current_app.logger.error(f"Config load error: {str(e)}")
            flash("Error loading configuration", "danger")
            return redirect(url_for("admin.user_list"))


def valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except ValueError:
        return False
