FROM python:3.10-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /app/config/idps /app/certs

WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install python dependencies
RUN pip install --upgrade pip --no-cache-dir && \
    pip install lxml signxml cryptography pysaml2 --no-cache-dir && \
    pip install --no-cache-dir -r requirements.txt

# Copy config files
COPY app/config/idps/ /app/config/idps/

# Copy application
COPY . .

# Generate certificates during build
RUN openssl req -x509 -newkey rsa:4096 -nodes \
    -out /app/certs/idp-cert.pem \
    -keyout /app/certs/idp-key.pem \
    -days 365 \
    -subj "/CN=localhost"

# Set environment variables for Docker
ENV KEY_PATH=/app/certs/idp-key.pem \
    CERT_PATH=/app/certs/idp-cert.pem

# Set permissions
RUN chmod -R 755 /app/config && \
    chmod +x /app/entrypoint.py

EXPOSE 5000

CMD ["python", "run.py"]
