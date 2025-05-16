#!/bin/bash
set -euxo pipefail  # Fail on errors and print commands
export IDP_HOST=${IDP_HOST:-localhost}
export IDP_PORT=${IDP_PORT:-5000}

# Generate key and cert
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /app/certs/idp-key.pem \
    -out /app/certs/idp-cert.pem \
    -days 365 \
    -subj "/CN=${IDP_HOST}" \
    -addext "subjectAltName = DNS:${IDP_HOST},IP:${IDP_HOST}"

# Validate files exist
if [ ! -f "/app/certs/idp-key.pem" ] || [ ! -f "/app/certs/idp-cert.pem" ]; then
  echo "🛑 Certificate generation failed!"
  exit 1
fi

# Verify PEM format
openssl x509 -noout -text -in /app/certs/idp-cert.pem || exit 1
openssl rsa -check -noout -in /app/certs/idp-key.pem || exit 1