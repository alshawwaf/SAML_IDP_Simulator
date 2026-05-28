FROM python:3.10-slim

# Install OS-level dependencies required by signxml and lxml
RUN apt-get update && apt-get install -y \
    openssl \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir lxml signxml cryptography pysaml2 && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure entrypoint is executable
RUN chmod +x entrypoint.py

# Environment variable paths (certs will be generated at runtime using IDP_HOST)
# Must match IDP_CERT/IDP_KEY in app/utils/path_config.py (CERTS_DIR = /app/app/certs)
ENV CERT_PATH=/app/app/certs/idp-cert.pem \
    KEY_PATH=/app/app/certs/idp-key.pem

# Expose the port Flask runs on
EXPOSE 5000

# Start the application through the runtime initializer
CMD ["python", "entrypoint.py"]
