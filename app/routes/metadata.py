from flask import Blueprint, Response, send_file
from app.utils.saml import IdPHandler
from app.utils.logger_main import log
from datetime import datetime
import os
from pathlib import Path

metadata_bp = Blueprint("metadata", __name__)


@metadata_bp.route("/metadata")
def metadata():
    """Serve dynamically generated SAML metadata"""
    try:
        idp_handler = IdPHandler()
        metadata_xml = idp_handler.generate_metadata()

        return Response(
            metadata_xml,
            mimetype="application/xml",
            headers={
                "Content-Disposition": "inline",  # ✅ Remove filename
                "Cache-Control": "no-cache, must-revalidate",
                "Last-Modified": datetime.utcnow().strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                ),
            },
        )
    except Exception as e:
        log.error(f"Metadata generation failed: {str(e)}", exc_info=True)
        return f"Metadata unavailable: {str(e)}", 500


@metadata_bp.route("/download-metadata")
def download_metadata():
    idp_handler = IdPHandler()
    metadata_xml = idp_handler.generate_metadata()
    return Response(
        metadata_xml,
        mimetype="application/xml",
        headers={"Content-Disposition": "attachment;filename=metadata.xml"},
    )


@metadata_bp.route("/download-cert")
def download_cert():
    """Serve IdP certificate with security headers"""
    try:
        # Resolve absolute path of cert (whether it's set in .env or default fallback)
        cert_env_path = os.getenv("CERT_PATH")
        cert_path = (
            Path(cert_env_path) if cert_env_path else Path("app/certs/idp-cert.pem")
        )
        abs_cert_path = cert_path.resolve(strict=True)

        return send_file(
            abs_cert_path,
            as_attachment=True,
            download_name="idp-certificate.pem",
            mimetype="application/x-pem-file",
            etag=False,
            last_modified=datetime.utcnow(),
        )

    except FileNotFoundError:
        log.error(f"Certificate file not found at: {cert_env_path}")
        return "Certificate unavailable", 404
    except Exception as e:
        log.error(f"Certificate download failed: {str(e)}")
        return "Service unavailable", 500
