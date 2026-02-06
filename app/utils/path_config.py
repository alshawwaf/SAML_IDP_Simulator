import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
APP_DIR = BASE_DIR / "app"
UTILS_DIR = APP_DIR / "utils"
CONFIG_DIR = APP_DIR / "config"
IDP_CONFIG_DIR = CONFIG_DIR / "idps"
CERTS_DIR = APP_DIR / "certs"
LOGS_DIR = BASE_DIR / "logs"
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"

# File paths
IDP_TEMPLATE = IDP_CONFIG_DIR / "idp-template.xml"
IDP_CONFIG_XML = IDP_CONFIG_DIR / "idp-config.xml"
IDP_CERT = CERTS_DIR / "idp-cert.pem"
IDP_KEY = CERTS_DIR / "idp-key.pem"
