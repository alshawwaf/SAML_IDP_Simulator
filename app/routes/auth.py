from flask import (
    Blueprint,
    request,
    render_template,
    session,
    current_app,
    redirect,
    url_for,
    make_response,
    send_from_directory,
)
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
import base64
import zlib
from lxml import etree
import time
from app.utils.user_manager import UserManager
from app.utils.saml import IdPHandler
from app.utils.logger_main import log
from signxml.exceptions import InvalidSignature, InvalidDigest
from functools import wraps

auth_bp = Blueprint("auth", __name__)

SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in") or session.get("account_type") != "admin":
            log.info("Admin login required", "warning")
            return redirect(url_for("admin.login"))
        return f(*args, **kwargs)

    return decorated_function


@auth_bp.route("/")
def index():
    """Landing page with service information"""
    return render_template("index.html")


@auth_bp.route("/login")
def login():
    """Direct login page entry point"""
    if session.get("saml_data"):
        return render_template("auth/login.html")
    return redirect(url_for("auth.index"))


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.index"))


@auth_bp.route("/sso", methods=["GET"])
def handle_saml_request():
    """Process SAML AuthnRequest from Check Point"""
    start = time.perf_counter()
    try:
        log.debug(f"Received SAMLRequest: {request.args.get('SAMLRequest')}")
        log.debug(f"HTTP Headers: {dict(request.headers)}")
        saml_request = unquote(request.args.get("SAMLRequest", ""))
        relay_state = request.args.get("RelayState", "")

        if not saml_request:
            log.warning("Empty SAMLRequest received")
            return (
                render_template(
                    "error.html", error="Missing SAML authentication request"
                ),
                400,
            )

        root = _decode_saml_request(saml_request)
        sp_entity_id, acs_url = _validate_saml_request(root)

        if not IdPHandler().validate_sp(sp_entity_id):
            log.warning(f"Untrusted SP attempt: {sp_entity_id}")
            return (
                render_template("error.html", error="Unauthorized service provider"),
                403,
            )

        session.clear()
        session.update(
            {
                "saml_data": {
                    "request_id": root.get("ID"),
                    "sp_entity_id": sp_entity_id,
                    "acs_url": acs_url,
                    "relay_state": relay_state,
                    "valid_until": datetime.now(timezone.utc) + timedelta(minutes=5),
                }
            }
        )

        return render_template("auth/login.html")

    except ValueError as e:
        log.error(f"Invalid SAML request: {str(e)}")
        return (
            render_template(
                "error.html", error=f"Invalid authentication request: {str(e)}"
            ),
            400,
        )
    except Exception as e:
        log.error(f"Unexpected error: {str(e)}", exc_info=True)
        return render_template("error.html", error="Internal server error"), 500

    finally:
        duration = time.perf_counter() - start
        log.info(f"/sso route processed in {duration:.3f} seconds")


@auth_bp.route("/login", methods=["POST"])
def handle_login():
    """Process user login and generate SAML response"""
    try:
        saml_data = session.get("saml_data")

        # Validate session data
        if not saml_data or datetime.now(timezone.utc) > saml_data.get("valid_until"):
            log.warning("Invalid or expired SAML session")
            return render_template("error.html", error="Session expired"), 401

        # Authenticate user
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            log.debug("Username / Password missing!")
            return render_template(
                "auth/login.html", error="Please enter both username and password"
            )

        # Get full user object with type information
        # TODO there is no error message in the portal for invalid users.
        user = UserManager.validate_user(username, password)
        if not user:
            log.debug("Failed to validate user")
            return render_template("auth/login.html", error="Invalid credentials")

        # Clear previous sessions
        session.clear()

        sp = IdPHandler().get_sp(saml_data["sp_entity_id"])
        if not sp:
            return render_template("error.html", error="Untrusted SP")

        response = IdPHandler().create_saml_response(
            user={
                "username": user["username"],
                "sp_entity_id": sp.entity_id,  # pass to assertion builder
                "attributes": {
                    "email": user["email"],
                    "first_name": user.get("first_name"),
                    "last_name": user.get("last_name"),
                    "groups": user.get("groups", []),
                },
            },
            in_response_to=saml_data["request_id"],
            sp_entity_id=sp.entity_id,
            destination=sp.acs_url,
        )
        # Set SAML user session
        session.update(
            {
                "account_type": "saml_user",
                "user_info": {
                    "username": user["username"],
                    "valid_until": datetime.now(timezone.utc) + timedelta(minutes=15),
                },
            }
        )

        # Immediately return SAML response to SP
        return render_template(
            "saml_post.html",
            saml_response=base64.b64encode(response).decode("utf-8"),
            acs_url=saml_data["acs_url"],
            relay_state=saml_data.get("relay_state", ""),
        )

    except (InvalidSignature, InvalidDigest) as e:
        log.error(f"Security error: {str(e)}")
        return render_template("error.html", error="Security failure"), 403
    except Exception as e:
        log.error(f"Error: {str(e)}")
        return render_template("error.html", error="Processing error"), 500


def _decode_saml_request(saml_request_encoded):
    start = time.perf_counter()
    try:
        # Add padding if needed
        saml_request_encoded += "=" * ((4 - len(saml_request_encoded) % 4) % 4)
        decoded = base64.urlsafe_b64decode(saml_request_encoded)

        try:
            xml_content = zlib.decompress(decoded, -15).decode("utf-8")
        except zlib.error:
            xml_content = decoded.decode("utf-8")

        parser = etree.XMLParser(resolve_entities=False, no_network=True)

        log.debug(f"Raw SAML Request:\n{xml_content}")

        return etree.fromstring(xml_content.encode(), parser=parser)
    except Exception as e:
        log.error(f"Decoding failed: {str(e)}\nInput: {saml_request_encoded[:100]}...")
        raise
    finally:
        duration = time.perf_counter() - start
        log.info(f"Decoded SAML request in {duration:.3f} seconds")


def _validate_saml_request(root):
    """Validate SAML AuthnRequest structure"""
    try:
        # Get configuration values safely
        saml_endpoint = current_app.config.get("SAML_ENDPOINT")
        if not saml_endpoint:
            raise ValueError("Missing SAML_ENDPOINT in configuration")

        # 1. Verify root element is AuthnRequest
        if root.tag != f"{{{SAML_NS['samlp']}}}AuthnRequest":
            raise ValueError(f"Invalid root element: {root.tag}")

        # 2. Verify required attributes
        required_attrs = ["ID", "Version", "IssueInstant"]
        for attr in required_attrs:
            if not root.get(attr):
                raise ValueError(f"Missing required attribute: {attr}")

        # 3. Validate Issuer element
        issuer = root.find(".//saml:Issuer", namespaces=SAML_NS)
        if issuer is None or not (issuer.text and issuer.text.strip()):
            raise ValueError("Missing or empty saml:Issuer")
        sp_entity_id = issuer.text.strip()

        # 4. Validate Destination
        received_destination = root.get("Destination")
        log.debug(
            f"Destination validation - Expected: {saml_endpoint}, Received: {received_destination}"
        )

        if received_destination and received_destination != saml_endpoint:
            raise ValueError(f"Invalid Destination: {received_destination}")

        # 5. Get ACS URL
        acs_url = root.get("AssertionConsumerServiceURL")
        if not acs_url:
            raise ValueError("Missing AssertionConsumerServiceURL")

        return sp_entity_id, acs_url

    except Exception as e:
        log.error(f"SAML request validation failed: {str(e)}")
        raise


@auth_bp.before_request
def set_session_defaults():
    """Initialize session values if missing"""
    if "account_type" not in session:
        session["account_type"] = "guest"
