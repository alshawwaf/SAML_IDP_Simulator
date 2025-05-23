from pathlib import Path
from signxml import XMLSigner, methods
from lxml import etree
from xml.sax.saxutils import escape
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from urllib.parse import urlparse
from app.utils.config_manager import IdPConfigManager
from app.utils.path_config import paths
from app.utils.logger_main import log
from jinja2 import Environment, FileSystemLoader
from app.utils.models import User
from app.utils.models import ServiceProvider


class IdPHandler:
    def __init__(self):
        self.config = IdPConfigManager.get_config()  # Use centralized config
        self._validate_certificates()

    def _validate_config_files(self):
        """Verify certificate files are readable"""
        try:
            with open(self.config["signing_cert_path"], "r") as f:
                f.read()
            with open(self.config["signing_key_path"], "r") as f:
                f.read()
        except Exception as e:
            raise RuntimeError(f"Configuration file validation failed: {str(e)}")

    def _load_dynamic_config(self):
        """Load configuration from dynamic YAML file"""
        config = IdPConfigManager.get_config()

        if not config:
            log.error("No IDP configuration found")
            raise RuntimeError("IDP configuration not initialized")

        required_fields = [
            "entity_id",
            "sso_service_url",
            "signing_cert_path",
            "signing_key_path",
            "trusted_sp",
        ]
        for field in required_fields:
            if field not in config:
                error_msg = f"Missing required configuration field: {field}"
                log.error(error_msg)
                raise ValueError(error_msg)

        # Initialize trusted_sp if not exists
        if "trusted_sp" not in config:
            config["trusted_sp"] = []
            IdPConfigManager.update_config(config)

        return config

    def add_trusted_sp(self, sp_entity_id, sp_acs_url):
        try:
            if "trusted_sp" not in self.config:
                self.config["trusted_sp"] = []

            # Update existing or add new
            existing = next(
                (
                    sp
                    for sp in self.config["trusted_sp"]
                    if sp["entity_id"] == sp_entity_id
                ),
                None,
            )

            if existing:
                existing["acs_url"] = sp_acs_url
                existing["updated_at"] = datetime.now(timezone.utc).isoformat()
            else:
                self.config["trusted_sp"].append(
                    {
                        "entity_id": sp_entity_id,
                        "acs_url": sp_acs_url,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )

            IdPConfigManager.update_config(self.config)
            log.info(f"Added new trusted SP: {sp_entity_id}")
            return True

        except Exception as e:
            log.error(f"Failed to add trusted SP: {str(e)}")
            raise

    def _validate_metadata_consistency(self, entity_descriptor):
        """Additional validation checks"""
        # Verify entityID matches certificate subject
        cert_subject = self._get_certificate_subject()
        entity_host = urlparse(self.config["entity_id"]).hostname
        if entity_host not in cert_subject:
            log.warning(
                "Certificate subject %s doesn't match entityID host %s",
                cert_subject,
                entity_host,
            )

    def _get_certificate_subject(self):
        """Extract certificate subject"""
        from cryptography.x509 import load_pem_x509_certificate

        cert_path = Path(self.config["signing_cert_path"])
        with cert_path.open("rb") as f:
            cert = load_pem_x509_certificate(f.read())
        return cert.subject.rfc4514_string()

    def _add_attribute(self, parent, name, value):
        attribute = etree.SubElement(
            parent,
            "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
            Name=escape(name),
            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        )
        etree.SubElement(
            attribute, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
        ).text = escape(str(value))

    def _sign_xml(self, xml_element):
        """
        Sign the XML element and return the canonical bytes **without**
        any post-signature pretty printing.  Reformatting even a single
        space or newline after signing will break the SHA-256 digest.
        """
        with open(self.config["signing_key_path"], "rb") as f:
            private_key = f.read()

        # Make the reference explicit so the digest is always over this node
        element_id = xml_element.get("ID")  # e.g. _3457…
        signed_element = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        ).sign(
            xml_element,
            key=private_key,
            reference_uri=f"#{element_id}",  # <- explicit target
        )

        # **NO pretty_print** – preserve the exact canonical form
        return etree.tostring(signed_element, encoding="utf-8")

    def _validate_certificates(self):
        """Validate certificate files exist AND are valid"""
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.x509 import load_pem_x509_certificate

        try:
            cert_path = Path(self.config["signing_cert_path"])
            key_path = Path(self.config["signing_key_path"])

            if not cert_path.exists():
                raise FileNotFoundError(f"Certificate missing: {cert_path}")
            if not key_path.exists():
                raise FileNotFoundError(f"Key missing: {key_path}")

            # Read certificate/key content using Path methods
            key = load_pem_private_key(key_path.read_bytes(), password=None)
            cert = load_pem_x509_certificate(cert_path.read_bytes())

            # Verify key matches certificate
            if cert.public_key().public_numbers() != key.public_key().public_numbers():
                raise ValueError("Certificate does not match private key")

        except Exception as e:
            log.error("Certificate validation failed: %s", str(e))
            raise

    def create_saml_response(
        self, user, in_response_to, sp_entity_id, destination=None
    ):

        try:
            # Get user from database
            db_user = User.query.filter_by(username=user["username"]).first()
            # Add groups to assertion
            user["groups"] = db_user.groups
            user["email"] = db_user.email
            user["first_name"] = db_user.first_name
            user["last_name"] = db_user.last_name

            if not self.validate_sp(sp_entity_id):
                raise ValueError(f"Untrusted SP: {sp_entity_id}")

            # Get SP configuration
            sp_config = ServiceProvider.query.filter_by(entity_id=sp_entity_id).first()
            if not sp_config:
                raise ValueError(
                    f"No SP configuration found for entity ID: {sp_entity_id}"
                )

            # Use configured ACS URL if destination not provided

            if destination is None:
                destination = sp_config.acs_url
                log.debug(f" Destinaton: {destination}")

            response = etree.Element(
                "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
                ID=f"_{uuid4().hex}",
                IssueInstant=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                Version="2.0",
                Destination=destination,
                InResponseTo=in_response_to,
            )
            # Add Issuer
            issuer = etree.SubElement(
                response, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
            )
            issuer.text = self.config["entity_id"]
            # Add Status
            status = etree.SubElement(
                response, "{urn:oasis:names:tc:SAML:2.0:protocol}Status"
            )
            status_code = etree.SubElement(
                status, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode"
            )
            status_code.attrib["Value"] = "urn:oasis:names:tc:SAML:2.0:status:Success"

            user["sp_entity_id"] = sp_entity_id

            # Add Assertion
            assertion = self._create_assertion(user, in_response_to, destination)

            # Sign the assertion *itself* so SPs llike Check Point
            signed_assertion_bytes = self._sign_xml(assertion)
            signed_assertion = etree.fromstring(signed_assertion_bytes)

            # Append the signed assertion (not the unsigned one)
            response.append(signed_assertion)

            #  Sign the whole response (outer signature)
            #     – nested signatures are allowed and Check Point likes
            log.debug(etree.tostring(response))
            return self._sign_xml(response)

        except Exception as e:
            log.error("SAML response creation failed: %s", str(e))
            raise

    def _create_assertion(self, user, in_response_to, destination):
        """Create SAML assertion"""
        assertion = etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
            ID=f"_{uuid4().hex}",
            IssueInstant=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            Version="2.0",
        )

        # Issuer
        issuer = etree.SubElement(
            assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        )
        issuer.text = self.config["entity_id"]

        # Subject
        subject = etree.SubElement(
            assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        )
        # Add NameID format for Check Point compatibility
        name_id = etree.SubElement(
            subject,
            "{urn:oasis:names:tc:SAML:2.0:assertion}NameID",
            Format="urn:oasis:names:tc:SAML:1.1:username-format:unspecified",
        )
        name_id.text = user["email"]  # Use username instead of email

        # AuthnStatement
        authn_statement = etree.SubElement(
            assertion,
            "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement",
            AuthnInstant=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            SessionIndex=f"_{uuid4().hex}",
        )

        # Add AuthnContextClassRef required by Check Point
        authn_context = etree.SubElement(
            authn_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext"
        )
        etree.SubElement(
            authn_context, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"
        ).text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

        subject_confirmation = etree.SubElement(
            subject,
            "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation",
            Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
        )

        etree.SubElement(
            subject_confirmation,
            "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
            NotOnOrAfter=(datetime.now(timezone.utc) + timedelta(minutes=5)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            Recipient=destination,
            InResponseTo=in_response_to,
        )

        # Conditions
        conditions = etree.SubElement(
            assertion,
            "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
            NotBefore=(datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            NotOnOrAfter=(datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        )

        sp_entity_id = user["sp_entity_id"]
        audience = etree.SubElement(
            conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction"
        )
        etree.SubElement(
            audience, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
        ).text = sp_entity_id  # Should come from SAML request

        # AttributeStatement
        sp = self.get_sp(sp_entity_id)
        attr_map = sp.attr_map

        attr_stmt = etree.SubElement(
            assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
        )

        for mapping in attr_map:
            claim = mapping["claim"]
            value_key = mapping["value"]

            value = user.get(value_key) or user.get("attributes", {}).get(value_key)
            if value is None:
                log.warning(
                    f"Attribute '{claim}' → field '{value_key}' not found in user: {user}"
                )

            if value is None:
                log.warning(f"User field '{value_key}' not found for claim '{claim}'")

            if isinstance(value, list):
                # Create a single attribute element with multiple values
                attribute = etree.SubElement(
                    attr_stmt,
                    "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
                    Name=escape(claim),
                    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                )
                for v in value:
                    etree.SubElement(
                        attribute,
                        "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue",
                    ).text = escape(str(v))
            elif value is not None:
                self._add_attribute(attr_stmt, claim, value)

        return assertion

    def generate_metadata(self, include_signature=True) -> bytes:
        try:
            entity_id = self.config["entity_id"]
            sso_url = self.config["sso_service_url"]

            # Load certificate content
            cert_path = Path(self.config["signing_cert_path"])
            with cert_path.open("rb") as f:
                cert = f.read()

            # Strip headers/footers and join to one line
            cert_base64 = b"".join(
                line for line in cert.splitlines() if b"-----" not in line
            ).decode()

            # Build XML
            md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
            ds_ns = "http://www.w3.org/2000/09/xmldsig#"
            nsmap = {None: md_ns, "ds": ds_ns}

            entity_descriptor = etree.Element(
                "{%s}EntityDescriptor" % md_ns,
                nsmap=nsmap,
                entityID=entity_id,
                ID="_idp-desc",
            )

            idp_sso_descriptor = etree.SubElement(
                entity_descriptor,
                "{%s}IDPSSODescriptor" % md_ns,
                protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
            )
            etree.SubElement(idp_sso_descriptor, "{%s}NameIDFormat" % md_ns).text = (
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            )

            # SSO Binding and Location
            etree.SubElement(
                idp_sso_descriptor,
                "{%s}SingleSignOnService" % md_ns,
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                Location=sso_url,
            )

            # Certificate
            key_descriptor = etree.SubElement(
                idp_sso_descriptor, "{%s}KeyDescriptor" % md_ns, use="signing"
            )
            key_info = etree.SubElement(key_descriptor, "{%s}KeyInfo" % ds_ns)
            x509_data = etree.SubElement(key_info, "{%s}X509Data" % ds_ns)
            x509_cert = etree.SubElement(x509_data, "{%s}X509Certificate" % ds_ns)
            x509_cert.text = cert_base64

            if include_signature:
                with open(self.config["signing_key_path"], "rb") as f:
                    private_key = f.read()

                signed_entity = XMLSigner(
                    method=methods.enveloped,
                    signature_algorithm="rsa-sha256",
                    digest_algorithm="sha256",
                    c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
                ).sign(entity_descriptor, key=private_key, reference_uri="#_idp-desc")
                return etree.tostring(signed_entity, encoding="utf-8")

            return etree.tostring(entity_descriptor, encoding="utf-8")

        except Exception as e:
            log.error("Metadata generation failed: %s", str(e))
            raise

    def get_sp(self, entity_id):
        return ServiceProvider.query.filter_by(entity_id=entity_id).first()

    def validate_sp(self, entity_id):
        return self.get_sp(entity_id) is not None
