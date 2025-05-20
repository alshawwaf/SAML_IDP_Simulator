# 🛡️ SAML IDP Simulator for Check Point

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)  [![SAML 2.0](https://img.shields.io/badge/SAML-2.0-green)](https://en.wikipedia.org/wiki/SAML_2.0)  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🚀 Overview

The **SAML IDP Simulator** is a modern Identity Provider emulator tailored for **Check Point environments** (Harmony, Quantum, CloudGuard, SASE). It provides a **production-grade SAML SSO experience** for:

- Security PoCs
- Workshops and demos
- Integration testing

✨ Featuring a full-featured **web admin portal**, **dynamic attribute mapping**, and **realistic SAML flows**, it's your best tool for simulating enterprise SAML logins.

---

![Demo](https://github.com/alshawwaf/SAML_IDP_Simulator/blob/main/assets/Demo-SC.gif)

---

## 🌟 Key Features

- 🔐 **SP-Initiated SSO** using signed SAML Response + Assertion  
- 🧩 **Dynamic Attribute Mapping** via admin UI (claim → user field)  
- 👤 **User Management** with modal-based edit/create/delete  
- 🧪 **Multi-SP Support** with isolated configuration per SP  
- 🔑 **X.509 Dual Signature** support  
- 🕸️ **Web Login Flow** simulates realistic browser-based authentication  
- 📁 **One-click Metadata / Certificate Download**  
- ⚙️ **Admin Portal** for easy control and visibility  

---

## 🧱 Architecture (SAML Flow)

```mermaid
sequenceDiagram
    participant SP as Service Provider (Check Point)
    participant Browser as User Browser
    participant IdP as Identity Provider (Simulator)

    Note over SP,Browser: SP-Initiated SSO

    SP->>+Browser: Redirect with AuthnRequest (Base64, POST)
    Browser->>+IdP: Send AuthnRequest to /sso
    IdP->>Browser: Login Page HTML
    Browser->>IdP: POST credentials
    IdP->>IdP: Validate credentials, fetch SP config
    IdP->>IdP: Generate SAML Assertion + Response
    IdP->>Browser: HTML Form with auto-submit to ACS URL
    Browser->>SP: POST SAMLResponse + RelayState
    SP->>SP: Validate signatures, parse Assertion
    SP-->>Browser: Authenticated session or portal
```


---

## 💡 Typical Use Case

1. Configure your Check Point and add a new Identity Provider Object
2. Trigger login from SmartConsole / Portal  
3. The simulator receives and parses the AuthnRequest  
4. User logs in via the web interface  
5. A signed SAML Response + Assertion is generated and POSTed back  
6. Check Point logs the user in ✅

---

## 🛠️ Setup Instructions

### 🔧 Requirements

- Python 3.8+
- Flask
- signxml, lxml, flask-wtf, flask-limiter
- All dependencies: `pip install -r requirements.txt`

### 📦 Install & Run

```bash
# Clone the repo
git clone https://github.com/alshawwaf/SAML-IDP-Simulator.git
cd SAML-IDP-Simulator

# Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run
python run.py
```

### 🐳 Optional: Run with Docker

```bash
docker build -t saml-idp-simulator .
docker run -p 5000:5000 \
  -e CERT_PATH=/app/certs/idp-cert.pem \
  -e KEY_PATH=/app/certs/idp-key.pem \
  saml-idp-simulator
```

### 🔄 SSL Toggle
Set `ENABLE_SSL=false` to run without HTTPS (useful behind a reverse proxy):

```bash
docker run -p 5000:5000 -e ENABLE_SSL=false saml-idp-simulator
```
---

## ⚙️ Configuration

### .venv File

```bash
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Vpn123!"
SECRET_KEY="Super-very-secret-key"
IDP_HOST="localhost"
IDP_PORT="5000"
DEFAULT_SP_ENTITY_ID="https://your-sp.example.com/acs/id/..."
DEFAULT_SP_ACS_URL="https://your-sp.example.com/acs/sso"
SSO_SERVICE_URL="https://localhost:5000/sso"
FLASK_DEBUG=1
```

---

## 🔐 Admin Portal

> 🧭 Navigate to `https://localhost:5000/admin`

### 🔹 SP Management
- Add/edit SPs with:
  - Name, Entity ID, ACS URL
  - Claim-to-user-field mapping
- Configure multiple SPs independently

### 🔹 User Management
- Add/edit/delete users
- Auto-populated field mappings
- Password hashing included

---

## 🔄 Endpoints

| Endpoint           | Description                      |
|--------------------|----------------------------------|
| `/sso`             | Handles incoming AuthnRequest    |
| `/login`           | Login form                       |
| `/logout`          | Logs the user out                |
| `/metadata`        | SAML metadata XML                |
| `/download-cert`   | Public certificate download      |
| `/admin`           | Admin UI                         |

---

## 🧪 Check Point Integration Steps

1. **In SmartConsole**:
   - Create an Identity Provider object
   - Set ACS URL and Entity ID
   - Upload metadata or public certificate

2. **In the Simulator**:
   - Add SP config via admin UI
   - Ensure ACS/Entity ID matches
   - Start login from SmartConsole → simulate SSO

✅ Ensure the user exists in both systems.

---

## 📄 License

Licensed under the [MIT License](LICENSE)

---

## 🙌 Contributions Welcome

Feel free to fork, improve, and submit PRs!

---

> Created by [@alshawwaf](https://github.com/alshawwaf) for internal Check Point use, PoC enablement, and community SAML simulation.

