import os
import base64
import zlib
from datetime import datetime, timedelta
from lxml import etree
from signxml import XMLSigner
from app.utils.path_config import IDP_CERT, IDP_KEY, IDP_TEMPLATE
from app.utils.config_manager import config_manager

class IdPHandler:
    def __init__(self):
        with open(IDP_CERT, 'rb') as f:
            self.cert = f.read()
        with open(IDP_KEY, 'rb') as f:
            self.key = f.read()

    def create_assertion(self, user_info, sp_info):
        now = datetime.utcnow()
        not_before = now - timedelta(minutes=5)
        not_after = now + timedelta(minutes=60)
        
        # Simplified Assertion generation logic
        assertion = f"""
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion123" IssueInstant="{now.isoformat()}Z" Version="2.0">
            <saml:Issuer>{config_manager.IDP_ENTITY_ID}</saml:Issuer>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user_info['email']}</saml:NameID>
            </saml:Subject>
            <saml:Conditions NotBefore="{not_before.isoformat()}Z" NotOnOrAfter="{not_after.isoformat()}Z">
                <saml:AudienceRestriction>
                    <saml:Audience>{sp_info['entity_id']}</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AttributeStatement>
                <saml:Attribute Name="email"><saml:AttributeValue>{user_info['email']}</saml:AttributeValue></saml:Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
        """
        return assertion

    def sign_response(self, response_xml):
        root = etree.fromstring(response_xml)
        signer = XMLSigner()
        signed_root = signer.sign(root, key=self.key, cert=self.cert)
        return etree.tostring(signed_root)

    def decode_request(self, saml_request_b64):
        decoded = base64.b64decode(saml_request_b64)
        try:
            return zlib.decompress(decoded, -15)
        except:
            return decoded
