"""SAML 2.0 Identity Provider logic.

Parses an incoming SP `AuthnRequest` and emits a SAML `Response` containing a
single **signed** `Assertion` (RSA-SHA256, exclusive C14N, enveloped signature).
The signing key/cert are the IdP's X.509 material in app/certs — the same trust
anchor advertised in /metadata, which Service Providers import and validate.

Design notes:
- The assertion is signed standalone, then placed into the Response. SAML
  mandates exclusive C14N precisely so a signed assertion stays valid when
  moved into a new parent document.
- `WantAssertionsSigned="true"` is what Check Point SPs request, so we sign the
  assertion (not the Response envelope).
"""
import base64
import uuid
import zlib
from datetime import datetime, timedelta

from lxml import etree
from signxml import XMLSigner, methods

from app.utils.path_config import IDP_CERT, IDP_KEY
from app.utils.config_manager import config_manager

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
NSMAP = {"samlp": SAMLP_NS, "saml": SAML_NS}

NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
ATTR_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
AUTHN_CTX_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    # SAML IDs must not start with a digit (xs:ID / NCName).
    return "_" + uuid.uuid4().hex


def _q(ns: str, tag: str) -> str:
    return f"{{{ns}}}{tag}"


class IdPHandler:
    def __init__(self):
        with open(IDP_CERT, "rb") as f:
            self.cert = f.read()
        with open(IDP_KEY, "rb") as f:
            self.key = f.read()

    # ------------------------------------------------------------------ inbound
    def decode_request(self, saml_request_b64: str) -> bytes:
        """Decode a SAMLRequest. HTTP-Redirect binding deflates the XML;
        HTTP-POST binding sends it raw. Try inflate, fall back to plain."""
        decoded = base64.b64decode(saml_request_b64)
        try:
            return zlib.decompress(decoded, -15)
        except zlib.error:
            return decoded

    def parse_request(self, saml_request_b64: str) -> dict:
        """Extract the request ID, issuer (SP entityID) and optional ACS URL.

        Parsed with a hardened parser (no DTD, no entity resolution, no network)
        so a malicious AuthnRequest can't trigger XXE / entity-expansion."""
        xml = self.decode_request(saml_request_b64)
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True,
            dtd_validation=False, load_dtd=False, huge_tree=False,
        )
        root = etree.fromstring(xml, parser=parser)
        issuer_el = root.find(_q(SAML_NS, "Issuer"))
        issuer = issuer_el.text.strip() if issuer_el is not None and issuer_el.text else None
        return {
            "request_id": root.get("ID"),
            "issuer": issuer,
            "acs_url": root.get("AssertionConsumerServiceURL"),
        }

    # ----------------------------------------------------------------- outbound
    def build_response(self, user_info: dict, sp_info: dict, request_id=None) -> str:
        """Return a base64-encoded, signed SAML Response (for HTTP-POST to ACS).

        user_info: {"email": str, "attributes": {name: [values...]}}
        sp_info:   {"entity_id": str, "acs_url": str}
        """
        now = datetime.utcnow()
        not_before = now - timedelta(minutes=5)
        not_after = now + timedelta(minutes=60)
        issuer = config_manager.effective_entity_id()
        acs_url = sp_info["acs_url"]
        audience = sp_info.get("entity_id") or ""
        assertion_id = _new_id()

        response = etree.Element(_q(SAMLP_NS, "Response"), nsmap=NSMAP)
        response.set("ID", _new_id())
        response.set("Version", "2.0")
        response.set("IssueInstant", _iso(now))
        response.set("Destination", acs_url)
        if request_id:
            response.set("InResponseTo", request_id)

        etree.SubElement(response, _q(SAML_NS, "Issuer")).text = issuer

        status = etree.SubElement(response, _q(SAMLP_NS, "Status"))
        etree.SubElement(status, _q(SAMLP_NS, "StatusCode")).set("Value", STATUS_SUCCESS)

        assertion = self._build_assertion(
            user_info, issuer, audience, acs_url, assertion_id,
            now, not_before, not_after, request_id,
        )
        response.append(self._sign_assertion(assertion))

        xml_bytes = etree.tostring(response, xml_declaration=False)
        return base64.b64encode(xml_bytes).decode("ascii")

    def _build_assertion(self, user_info, issuer, audience, acs_url, assertion_id,
                         now, not_before, not_after, request_id):
        assertion = etree.Element(_q(SAML_NS, "Assertion"), nsmap={"saml": SAML_NS})
        assertion.set("ID", assertion_id)
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", _iso(now))

        # Issuer MUST be the first child (ds:Signature follows it after signing).
        etree.SubElement(assertion, _q(SAML_NS, "Issuer")).text = issuer

        # Subject + bearer SubjectConfirmation bound to this request and ACS.
        subject = etree.SubElement(assertion, _q(SAML_NS, "Subject"))
        nameid = etree.SubElement(subject, _q(SAML_NS, "NameID"))
        nameid.set("Format", NAMEID_EMAIL)
        nameid.text = user_info["email"]
        subj_conf = etree.SubElement(subject, _q(SAML_NS, "SubjectConfirmation"))
        subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        scd = etree.SubElement(subj_conf, _q(SAML_NS, "SubjectConfirmationData"))
        scd.set("NotOnOrAfter", _iso(not_after))
        scd.set("Recipient", acs_url)
        if request_id:
            scd.set("InResponseTo", request_id)

        # Conditions / audience.
        conditions = etree.SubElement(assertion, _q(SAML_NS, "Conditions"))
        conditions.set("NotBefore", _iso(not_before))
        conditions.set("NotOnOrAfter", _iso(not_after))
        if audience:
            ar = etree.SubElement(conditions, _q(SAML_NS, "AudienceRestriction"))
            etree.SubElement(ar, _q(SAML_NS, "Audience")).text = audience

        # AuthnStatement.
        authn = etree.SubElement(assertion, _q(SAML_NS, "AuthnStatement"))
        authn.set("AuthnInstant", _iso(now))
        authn.set("SessionIndex", assertion_id)
        authn_ctx = etree.SubElement(authn, _q(SAML_NS, "AuthnContext"))
        etree.SubElement(authn_ctx, _q(SAML_NS, "AuthnContextClassRef")).text = AUTHN_CTX_PASSWORD

        # AttributeStatement from the SP's claim mapping.
        attributes = user_info.get("attributes") or {}
        if attributes:
            attr_stmt = etree.SubElement(assertion, _q(SAML_NS, "AttributeStatement"))
            for name, values in attributes.items():
                attr = etree.SubElement(attr_stmt, _q(SAML_NS, "Attribute"))
                attr.set("Name", name)
                attr.set("NameFormat", ATTR_FORMAT_BASIC)
                for v in values:
                    etree.SubElement(attr, _q(SAML_NS, "AttributeValue")).text = str(v)
        return assertion

    def _sign_assertion(self, assertion):
        """Enveloped RSA-SHA256 / exclusive-C14N signature over the assertion.
        Repositions ds:Signature to directly follow Issuer (SAML schema order)."""
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        )
        signed = signer.sign(assertion, key=self.key, cert=self.cert)
        sig = signed.find(_q(DS_NS, "Signature"))
        if sig is not None:
            signed.remove(sig)
            signed.insert(1, sig)  # index 0 is Issuer
        return signed
