# Changelog

## [Unreleased] — 2026-06-06

### Added
- **First-class Groups (Entra/Okta-style).** Groups are now directory objects with a
  stable **Group ID** (UUID — the Entra `objectId` / Okta group id equivalent), display
  name, description, and a member list, managed from a new **Groups** admin page (and over
  SCIM — they're the same entities). Membership feeds the SAML assertion through two new
  claim sources, `group_names` (display names, Okta-style) and `group_ids` (UUIDs,
  Entra-style), so a Service Provider access role (e.g. SmartConsole) can authorize a
  **whole group**, not just individual users. Dashboard gains a Groups count.
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
- **Retired the free-text `User.groups` list.** The per-user comma-separated field is
  replaced by membership against first-class Groups. A one-time, idempotent startup
  migration materializes existing labels into real groups (UUIDs + membership) and
  repoints every Service Provider's group claim from `groups` to `group_names`. The
  legacy column is left dormant (not dropped); the SAML emission code path is unchanged.
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
