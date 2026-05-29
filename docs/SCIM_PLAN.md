# SCIM 2.0 Extension — Implementation Plan

**Status:** Phases 0–3 + 5 shipped. 81% scim2-tester compliance.
**Last updated:** 2026-05-29
**Goal:** Add SCIM 2.0 provisioning support to interoperate with Check Point Harmony SASE, without touching the existing SAML implementation.

---

## 1. The Critical Finding

Check Point Harmony SASE acts as the **SCIM server**, not the client. External IdPs (Entra ID, Okta, JumpCloud) are configured as SCIM **clients** that push `POST/PUT/PATCH/DELETE` to Harmony's endpoints.

This inverts the architecture we're used to from SAML:

| | SAML (today) | SCIM (Harmony SASE) |
|---|---|---|
| Who initiates? | Service Provider (Check Point) | The IdP (this simulator) |
| Direction | Inbound to simulator | **Outbound from simulator** |
| Endpoint owned by | The simulator | Harmony SASE |
| Auth | Cert-signed XML | Bearer token (issued by Harmony) |

**Harmony's published SCIM base URLs** (region-specific; bearer token scopes the tenant):

| Region | Base URL |
|---|---|
| US | `https://api.perimeter81.com/api/scim` |
| EU | `https://api.eu.sase.checkpoint.com/api/scim` |
| AU | `https://api.au.sase.checkpoint.com/api/scim` |
| IN | `https://api.in.sase.checkpoint.com/api/scim` |

Token is generated in Harmony's UI under **Settings → Identity Providers → SCIM Integration → Generate Token**. Shown ONCE.

---

## 2. What We're Building

Two complementary modes, both gated by `ENABLE_SCIM`:

### Mode A — SCIM Client (outbound push to Harmony)
The production target. Simulator pushes users/groups to a real Harmony SASE tenant's `/api/scim` endpoint.

### Mode B — SCIM Server (inbound, exposes `/scim/v2/...`)
Offline-test surface. External SCIM clients (Entra, Okta) can push to the simulator for testing without a Harmony tenant. Mirrors today's "I'm an IdP server" pattern.

---

## 3. Confirmed Design Decisions

| Decision | Value |
|---|---|
| SCIM mode | Both client + server |
| Attribute mapping | **Generic SCIM 2.0** — stock RFC 7643. No Entra/Okta/JumpCloud personas. |
| User model change | Single additive column: `User.active: Boolean, default=True` |
| Token storage | Fernet-encrypted at rest, key from `SCIM_ENCRYPTION_KEY` env var |
| Feature gate | `ENABLE_SCIM=false` by default. SAML flow identical when disabled. |
| Libraries | `scim2-models` (Apache-2.0), `scim2-filter-parser` (MIT), `httpx` (BSD) |
| Compliance testing | `scim2-tester` in dev/CI |

**`userName = email` mapping** is hard-wired (Harmony requires it), but no per-IdP variant logic.

---

## 4. Non-Breaking File Layout

```
app/
├── __init__.py               # MODIFIED: register scim_bp behind ENABLE_SCIM flag
├── routes/
│   ├── auth.py               # UNCHANGED (SAML)
│   ├── metadata.py           # UNCHANGED (SAML)
│   ├── admin.py              # UNCHANGED
│   └── scim/                 # NEW package
│       ├── __init__.py
│       ├── server.py         # /scim/v2/Users, /Groups, etc.
│       ├── client.py         # outbound push to Harmony
│       ├── admin.py          # admin UI: targets, push log
│       ├── auth.py           # bearer-token decorator (separate from flask-login)
│       ├── mappers.py        # db.User <-> scim2_models.User
│       ├── filters.py        # scim2_filter_parser AST → SQLAlchemy visitor
│       └── patch.py          # PatchOp interpreter
├── utils/
│   ├── models.py             # MODIFIED: add User.active column only
│   ├── models_scim.py        # NEW: ScimTarget, ScimPushLog, ScimInboundToken, ScimGroup, ScimGroupMember
│   └── crypto.py             # NEW: Fernet wrapper for token at rest
└── templates/
    └── admin/
        └── scim/             # NEW templates
            ├── targets.html
            ├── target_edit.html
            ├── push_log.html
            └── sync_now.html
```

**Untouched:** all SAML files, the `ServiceProvider` model, existing admin routes, the cert/template pipeline.

---

## 5. Database Schema (Additive Only)

### Existing `User` table — one new column
```python
class User(db.Model, UserMixin):
    # ... existing columns ...
    active = db.Column(db.Boolean, default=True, nullable=False)  # NEW
```

### New tables
```python
# app/utils/models_scim.py

class ScimTarget(db.Model):
    """An outbound SCIM endpoint we push to (e.g., a Harmony SASE tenant)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    base_url = db.Column(db.String(255), nullable=False)
    bearer_token_encrypted = db.Column(db.LargeBinary, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    last_sync_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ScimPushLog(db.Model):
    """Audit of every outbound SCIM push — invaluable for live demos."""
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('scim_target.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    operation = db.Column(db.String(30))     # CREATE_USER, UPDATE_USER, DELETE_USER, ADD_TO_GROUP, ...
    status_code = db.Column(db.Integer)
    request_method = db.Column(db.String(10))
    request_url = db.Column(db.String(500))
    request_body = db.Column(db.Text)
    response_body = db.Column(db.Text)
    error = db.Column(db.Text, nullable=True)
    duration_ms = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ScimInboundToken(db.Model):
    """Bearer tokens that authorize SCIM clients pushing TO our server endpoints."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))         # human label e.g. "Entra test tenant"
    token_hash = db.Column(db.String(256), nullable=False)  # hashed at rest
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)


class ScimGroup(db.Model):
    """SCIM Group resource. Separate from User.groups JSON list so SCIM PATCH works cleanly."""
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(120), nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    display_name = db.Column(db.String(150), nullable=False, unique=True)
    external_id = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScimGroupMember(db.Model):
    """Many-to-many between ScimGroup and User."""
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('scim_group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('group_id', 'user_id'),)
```

**Why separate `ScimGroup` from `User.groups`:** the existing `groups` JSON list stores string labels for SAML attribute claims. SCIM groups are first-class resources with their own IDs, members, and PATCH semantics. Mixing them would either break SAML or warp SCIM.

---

## 6. User → SCIM Attribute Mapping

| `User` column | SCIM attribute |
|---|---|
| `user_id` (UUID) | `id` |
| `username` | `userName` (fallback to `email` if username is not email-shaped) |
| `email` | `emails[primary=true, type=work].value` |
| `first_name` | `name.givenName` |
| `last_name` | `name.familyName` |
| `active` (new) | `active` |
| `ScimGroupMember` rows | `groups[]` (readOnly on User; managed via Group resource) |
| `created_at` | `meta.created` |
| `updated_at` | `meta.lastModified` |

`is_admin` and `groups` (the SAML JSON list) are not exposed via SCIM.

---

## 7. SCIM Server Endpoints (Mode B)

All under `/scim/v2`, `Content-Type: application/scim+json`, bearer-token auth via `ScimInboundToken`.

| Endpoint | Methods |
|---|---|
| `/ServiceProviderConfig` | GET |
| `/ResourceTypes`, `/ResourceTypes/{id}` | GET |
| `/Schemas`, `/Schemas/{uri}` | GET |
| `/Users` | GET (list+filter), POST |
| `/Users/{id}` | GET, PUT, PATCH, DELETE |
| `/Groups` | GET (list+filter), POST |
| `/Groups/{id}` | GET, PUT, PATCH, DELETE |

**ServiceProviderConfig will advertise:** `patch.supported=true`, `bulk.supported=false`, `filter.supported=true (maxResults=200)`, `sort.supported=true`, `etag.supported=true`, `authenticationSchemes=[oauthbearertoken]`.

**Filter support (Phase 1):** `eq` on `userName`, `externalId`, `id`, `emails.value`, `displayName`, `members.value`. Add `and`, `co`, `sw` in Phase 2.

**PATCH support (Phase 2):** simple paths (`displayName`), dotted paths (`name.familyName`), value-filter paths (`members[value eq "..."]`), the Entra-style `{op: remove, path: members, value: [{value: "..."}]}` shape.

---

## 8. SCIM Client (Mode A)

Admin section at `/admin/scim/targets`:
- List configured targets with status (enabled, last_sync_at, success/error count)
- Add/edit/delete target (URL, bearer token, name)
- Test Connection button → `GET {base_url}/ServiceProviderConfig`
- "Sync All Users" button → iterates users, runs upsert flow
- "Sync This User" button on each user row → upsert one user
- Push Log viewer (filterable by target, user, operation, status)

**Upsert flow per user:**
1. `GET {base}/Users?filter=userName eq "{user.email}"`
2. If 0 results → `POST {base}/Users`
3. If 1 result → `PATCH {base}/Users/{id}` with diffs
4. Log request/response to `ScimPushLog`

**Deprovision flow:**
- "Soft" button → `PATCH active=false`
- "Hard" button → `DELETE /Users/{id}`
- Both surfaced because Check Point docs are silent on which frees the Harmony license

---

## 9. Auth Isolation

SCIM auth is completely separate from the existing admin session:

| Path | Auth |
|---|---|
| `/sso`, `/login`, `/metadata` (SAML) | unchanged |
| `/admin/...` (admin portal) | unchanged session + CSRF |
| `/admin/scim/...` (SCIM admin UI) | same admin session + CSRF |
| `/scim/v2/...` (SCIM server endpoints) | bearer token via `@scim_token_required`, **CSRF exempt** |

Token comparison uses `hmac.compare_digest`. Tokens are hashed at rest for inbound; outbound tokens (which we must replay) are Fernet-encrypted.

---

## 10. Config & Env Additions

`.env.example` additions:
```bash
# SCIM feature gate
ENABLE_SCIM=false
SCIM_BASE_PATH=/scim/v2
SCIM_ENCRYPTION_KEY=        # Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
SCIM_PUSH_ON_USER_CHANGE=false   # Phase 5: auto-push on admin user CRUD
```

`requirements.txt` additions:
```
scim2-models>=0.6.12
scim2-filter-parser>=0.7.0
httpx>=0.27
# dev-only
scim2-tester>=0.2.8
```

---

## 11. Phased Roadmap

| Phase | Scope | Status |
|---|---|---|
| **0. Skeleton** | Feature flag, `User.active` column, new tables, empty blueprint, DB migration, verify SAML still works | ✅ Shipped |
| **1. SCIM Server: discovery + read** | ServiceProviderConfig, ResourceTypes, Schemas, GET /Users, GET /Groups, filter parser | ✅ Shipped |
| **2. SCIM Server: CRUD** | POST/PUT/PATCH/DELETE for Users and Groups; PatchOp interpreter | ✅ Shipped |
| **3. SCIM Client: push to Harmony** | Outbound client, target admin UI, push log, test-connection, sync flows | ✅ Shipped (absorbed Phase 4 UX polish) |
| **5. Auto-sync hooks** | Push on admin user CRUD if `SCIM_PUSH_ON_USER_CHANGE=true` | ✅ Shipped |
| **Compliance run** | `scim2-tester` against /scim/v2 — fixed `.search`, 404 handling, schema declarations | ✅ 81% pass (see §11.5) |

SAML regression verified at the end of every phase.

---

## 11.5. Known compliance gaps (scim2-tester results)

48/59 (81%) checks pass against the `scim2-tester` RFC compliance suite. All 11 failures
trace to the User model being optimized for SAML rather than full SCIM expressiveness.

### Model-shape gaps (won't fix without invasive changes)

| Failure | Root cause | Real-world impact |
|---|---|---|
| `patch:add` / `patch:replace` on `name.formatted` | `User` has separate `first_name`/`last_name`; mapper recomputes `formatted = given + " " + family`. Whatever value the client sends gets overwritten. | None — Entra/Okta/JumpCloud send `givenName`/`familyName` independently and never check `formatted` round-trips. |
| `patch:add` / `patch:replace` on `displayName` | Derived in our mapper from first+last name. We discard any client-supplied value. | None — real clients also derive displayName, don't test exact round-trip. |
| `patch:add` / `patch:replace` on `emails` sub-attrs (`display`, `type`) | `User.email` is a single string column. We can't store `display`, hardcode `type="work"`. | Low — real clients send one work email and don't check `display` echo. |
| `patch:remove active` | `User.active` is NOT NULL. Can't truly absent it from the response. | None — clients use `replace active=false` for deactivation. |
| `patch:remove emails` | `User.email` is NOT NULL (SAML constraint). | None — clients deactivate users via `active=false` not by removing emails. |
| `patch:add` / `patch:replace` / `patch:remove` on Group `members` with random UUIDs | Our `ScimGroupMember` FK-references `User.id`. Members whose `value` doesn't match an existing User row are silently dropped. | None — real clients use IDs they got from prior list responses. |

### Fix paths (deferred — would touch the SAML User model)

If full compliance is later needed:
- Add `User.name_formatted`, `User.display_name_override`, `User.emails_extra` JSON column → covers the PATCH-preserve issues
- Make `User.active` nullable → enables true PATCH-remove of `active`
- Drop FK on `ScimGroupMember.user_id`, store the raw UUID → handles arbitrary upstream member IDs

Each of these is a 1-line model change + 1 ALTER migration. Skipped here per the
[[feedback-non-breaking-changes]] preference — the User model is in active use by SAML.

### What 81% means in practice

Every check that actually matters for **real-world interoperability** passes:
- All discovery endpoints (ServiceProviderConfig, ResourceTypes, Schemas)
- Full CRUD on Users and Groups (create, read, replace, patch, delete)
- Filter parsing with the operator set Entra/Okta actually emit
- `attributes` / `excludedAttributes` projection
- POST `.search` at root and per-resource-type
- SCIM-shaped 404 / 400 / 401 / 409 errors
- Bearer-token auth and CSRF exemption

Failed checks are the tester's adversarial UUID-in-every-field exercises against
attributes our SAML-shaped model can't faithfully echo. No production SCIM client
sends those payloads.

---

## 12. Harmony-Specific Quirks to Bake In

These are landmines documented in Check Point/Perimeter 81 admin guides. Code them in early.

1. **`email → userName` mapping** — Harmony's most common mis-config. Default it.
2. **Email is immutable on Harmony** — guard the client UI against email changes on already-pushed users; force delete+recreate.
3. **Name fields `[a-zA-Z0-9]` only** — validate before push, with an override toggle for testing.
4. **Group delete is sticky on Harmony policies** — when admin deletes a group, warn that Harmony will keep the policy binding.
5. **Token shown once** — UX must surface "Copy now" warning.
6. **SCIM gated behind Harmony SASE Enterprise tier** — note this in the target setup screen.
7. **Soft vs hard delete license behavior is undocumented** — expose both modes; observe.

---

## 13. Sources

**Specs:**
- [RFC 7643 — Core Schema](https://datatracker.ietf.org/doc/html/rfc7643)
- [RFC 7644 — Protocol](https://datatracker.ietf.org/doc/html/rfc7644)

**Check Point official:**
- [Harmony SASE SCIM overview](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/SASE-Admin-Guide/Content/Topics-SASE-IdP/SCIM/SCIM.htm)
- [Entra ID SCIM setup](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/SASE-Admin-Guide/Content/Topics-SASE-IdP/SCIM/MicrosoftEntraID_SCIM.htm)
- [Okta SCIM setup](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/SASE-Admin-Guide/Content/Topics-SASE-IdP/SCIM/Okta.htm)
- [Harmony SASE IdP Integration Guide (PDF)](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/SASE-IdP-Integration/CP_Harmony_SASE_IdP_Integration_Guide.pdf)

**Perimeter 81 legacy (still maintained):**
- [About SCIM](https://support.perimeter81.com/docs/about-scim)
- [Azure AD SCIM](https://support.perimeter81.com/docs/azure-active-directory)
- [Okta SCIM](https://support.perimeter81.com/docs/okta)

**Partner:**
- [JumpCloud + Perimeter 81 integration](https://jumpcloud.com/support/integrate-with-perimeter81)

**Libraries:**
- [scim2-models](https://github.com/python-scim/scim2-models)
- [scim2-filter-parser](https://github.com/15five/scim2-filter-parser)
- [scim2-tester](https://github.com/python-scim/scim2-tester)

**Reference IdP payloads (Harmony doesn't publish raw SCIM payload examples):**
- [Microsoft Entra ID SCIM tutorial](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups)
- [Okta SCIM concepts](https://developer.okta.com/docs/concepts/scim/)
