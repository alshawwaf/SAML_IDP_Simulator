from flask import Blueprint, Response, send_file
from app.utils.saml import IdPHandler
from app.utils.logger_main import log
from app.utils.path_config import paths
from datetime import datetime
import os
from pathlib import Path

metadata_bp = Blueprint("metadata", __name__)


@metadata_bp.route("/metadata")
def metadata():
    """Serve dynamically generated SAML metadata"""
    try:
        # Generate fresh metadata with security headers
        idp_handler = IdPHandler()

        metadata_xml = idp_handler.generate_metadata()

        response = Response(
            metadata_xml,
            mimetype="application/xml",
            headers={
                "Content-Disposition": "inline; filename=metadata.xml",
                "Cache-Control": "no-cache, must-revalidate",
                "Last-Modified": datetime.utcnow().strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                ),
            },
        )
        return response

    except Exception as e:
        log.error(f"Metadata generation failed: {str(e)}", exc_info=True)
        return f"Metadata unavailable: {str(e)}", 500


@metadata_bp.route("/download-cert")
def download_cert():
    """Serve IdP certificate with security headers"""
    try:
        BASE_DIR = Path(__file__).parent.parent
        cert_path = os.getenv("CERT_PATH", str(BASE_DIR / "certs" / "idp-cert.pem"))
        return send_file(
            cert_path,
            as_attachment=True,
            download_name="idp-certificate.pem",
            mimetype="application/x-pem-file",
            etag=False,
            last_modified=datetime.utcnow(),
        )
    except FileNotFoundError:
        log.error("Certificate file not found")
        return "Certificate unavailable", 404
    except Exception as e:
        log.error(f"Certificate download failed: {str(e)}")
        return "Service unavailable", 500
