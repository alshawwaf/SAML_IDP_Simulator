FROM python:3.10-slim

# Install OS-level dependencies required by signxml and lxml
RUN apt-get update && apt-get install -y \
    openssl \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies (all pinned in requirements.txt).
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure entrypoint is executable
RUN chmod +x entrypoint.py

# Environment variable paths (certs will be generated at runtime using IDP_HOST)
# Must match IDP_CERT/IDP_KEY in app/utils/path_config.py (CERTS_DIR = /app/app/certs)
ENV CERT_PATH=/app/app/certs/idp-cert.pem \
    KEY_PATH=/app/app/certs/idp-key.pem \
    USE_GUNICORN=true

# Expose the web port plus the AAA protocol ports (RADIUS UDP, TACACS+ TCP).
EXPOSE 5000
EXPOSE 1812/udp
EXPOSE 1813/udp
EXPOSE 4949/tcp

# Start the application through the runtime initializer
CMD ["python", "entrypoint.py"]
