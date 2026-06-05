# Changelog

## [Unreleased] — 2026-06-04

### Added
- **Real SAML 2.0 signed-assertion SSO flow.** `/sso` parses the SP `AuthnRequest`
  (hardened, XXE-safe parser), resolves the Service Provider by issuer, and stores
  the request context in the session. `/login` builds a SAML `Response` with a
  **signed `Assertion`** (RSA-SHA256, exclusive C14N, enveloped signature placed
  after `Issuer`), the SP's `attr_map` claims, bearer `SubjectConfirmation`,
  `Conditions`/audience, `AuthnStatement`, and `RelayState` round-trip, then
  auto-POSTs it to the SP's ACS URL. Verified locally against the IdP cert.
- Login rate limiting via the bundled Flask-Limiter — `/admin/login` (10/min),
  `/login` (30/min).
- gunicorn as the container's WSGI server (`USE_GUNICORN=true`, `GUNICORN_WORKERS`).
- MIT `LICENSE` (previously only referenced by the README).
- `prefers-reduced-motion` CSS guard; the SSO login page now shows the requesting
  SP's name.

### Changed
- `FLASK_DEBUG` now defaults to `false` (was `true`).
- `SECRET_KEY` is auto-generated and persisted to the data volume when unset
  (stable across redeploys); the hardcoded value was removed from `docker-compose.yml`.
- Dockerfile installs only the pinned `requirements.txt` (dropped the unused
  `pysaml2` and redundant unpinned installs).

### Security
- Removed a hardcoded `SECRET_KEY` from version control (it signs sessions and
  derives the SCIM token-encryption key).
- Stopped tracking `users.db`; `.gitignore` now covers `*.db`, `/data/`, `instance/`.
- Hardened the SAML request parser against XML external-entity (XXE) attacks.

### Fixed
- SAML SSO previously returned a literal placeholder (`SAMLResponse="..."`) instead
  of a real assertion — the core feature is now functional.

> Note: the IdP metadata and signing certificate (the trust anchor Service
> Providers import) are unchanged, so existing configured SPs need no re-import.
