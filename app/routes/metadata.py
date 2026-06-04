from flask import Blueprint, Response, render_template, make_response
from jinja2 import Template
from app.utils.config_manager import config_manager
from app.utils.path_config import IDP_CERT, IDP_TEMPLATE
import os

metadata_bp = Blueprint('metadata', __name__)

def get_metadata_xml():
    """Generate the SAML metadata XML"""
    with open(IDP_CERT, 'r') as f:
        cert_data = f.read().replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '')
    
    with open(IDP_TEMPLATE, 'r') as f:
        template_str = f.read()
    
    template = Template(template_str)
    return template.render(
        entity_id=config_manager.effective_entity_id(),
        cert_content=cert_data,
        sso_service_url=config_manager.effective_sso_url()
    )

@metadata_bp.route('/metadata')
def metadata():
    xml = get_metadata_xml()
    return Response(xml, mimetype='text/xml')

@metadata_bp.route('/download-metadata')
def download_metadata():
    """Download the metadata as an XML file"""
    xml = get_metadata_xml()
    response = make_response(xml)
    response.headers['Content-Type'] = 'application/xml'
    response.headers['Content-Disposition'] = 'attachment; filename=idp-metadata.xml'
    return response

@metadata_bp.route('/')
def index():
    return render_template('index.html', config=config_manager.get_all_config())
