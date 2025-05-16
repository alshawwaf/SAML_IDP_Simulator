#!/usr/bin/env python3
import os
from pathlib import Path
from urllib.parse import urlparse
from lxml import etree
from app.utils.path_config import paths
from app.utils.logger_main import log
from urllib.parse import unquote


class IdPConfigManager:
    CONFIG_PATH = paths.config_dir / "idps" / "idp-config.xml"

    @classmethod
    def initialize(cls):
        """Create default XML config if missing"""
        if not cls.CONFIG_PATH.exists():
            # Decode URL-encoded characters
            default_entity_id = unquote(os.getenv("DEFAULT_SP_ENTITY_ID", ""))
            default_acs_url = unquote(os.getenv("DEFAULT_SP_ACS_URL", ""))

            log.debug(f"Decoded SP Entity ID: {default_entity_id}")

            default_config = {
                "entity_id": f"https://{os.getenv('IDP_HOST', 'localhost')}:{os.getenv('IDP_PORT', '5000')}",
                "sso_service_url": f"https://{os.getenv('IDP_HOST', 'localhost')}:{os.getenv('IDP_PORT', '5000')}/sso",
                "signing_cert_path": str(paths.cert_dir / "idp-cert.pem"),
                "signing_key_path": str(paths.cert_dir / "idp-key.pem"),
                "trusted_sp": [
                    {
                        "entity_id": default_entity_id,
                        "acs_url": default_acs_url,
                    },
                ],
            }

            cls.update_config(default_config)
            log.info("Created default XML configuration")

    @classmethod
    def get_config(cls):
        """Parse and return XML configuration"""
        try:
            if not cls.CONFIG_PATH.exists():
                return None

            tree = etree.parse(str(cls.CONFIG_PATH))
            root = tree.getroot()

            return {
                "entity_id": root.get("entityID"),
                "sso_service_url": root.find(".//{*}SingleSignOnService").get(
                    "Location"
                ),
                "signing_cert_path": str(paths.cert_dir / "idp-cert.pem"),
                "signing_key_path": str(paths.cert_dir / "idp-key.pem"),
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
        except Exception as e:
            log.error(f"XML config parse failed: {str(e)}")
            return None

    @classmethod
    def update_config(cls, new_config):
        """Update XML configuration with validation"""
        cls.validate_config(new_config)

        # Generate new XML structure
        root = etree.Element("EntityDescriptor", entityID=new_config["entity_id"])
        idp_desc = etree.SubElement(root, "IDPSSODescriptor")

        # Add SSO service
        etree.SubElement(
            idp_desc,
            "SingleSignOnService",
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Location=new_config["sso_service_url"],
        )

        # Add trusted SPs
        for sp in new_config["trusted_sp"]:
            sp_desc = etree.SubElement(root, "SPSSODescriptor")
            etree.SubElement(sp_desc, "EntityID").text = sp["entity_id"]
            etree.SubElement(
                sp_desc,
                "AssertionConsumerService",
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                Location=sp["acs_url"],
            )

        # Write to file
        cls.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tree = etree.ElementTree(root)
        tree.write(str(cls.CONFIG_PATH), pretty_print=True)
        log.info("XML configuration updated")

    @staticmethod
    def validate_config(config):
        """Validate configuration structure"""
        required = {
            "entity_id": str,
            "sso_service_url": str,
            "signing_cert_path": str,
            "signing_key_path": str,
            "trusted_sp": list,
        }

        # Field existence check
        missing = [k for k in required if k not in config]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        # File existence check
        for key in ["signing_cert_path", "signing_key_path"]:
            if not Path(config[key]).exists():
                raise ValueError(f"File not found: {config[key]}")

        # URL validation
        for url_key in ["entity_id", "sso_service_url"]:
            parsed = urlparse(config[url_key])
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError(f"Invalid URL format: {url_key}")

        # SP validation
        for sp in config["trusted_sp"]:
            if not all(k in sp for k in ["entity_id", "acs_url"]):
                raise ValueError("SP config requires entity_id and acs_url")
            parsed = urlparse(sp["entity_id"])
            log.debug(
                f"Parsed SP entity_id: Scheme={parsed.scheme}, Netloc={parsed.netloc}"
            )
            if not parsed.netloc:
                raise ValueError(f"Invalid SP entity_id: {sp['entity_id']}")

        return True
