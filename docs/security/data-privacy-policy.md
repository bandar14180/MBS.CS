# Data Privacy Policy (Backend)

This document describes how the MBS.CS backend collects, protects, retains, and
disposes of personal data, and the data-subject rights it implements. It reflects the
behavior of the `apps/api` service and is kept in sync with the code it describes.

> Scope: personal data of platform **users** (authentication and account records).
> Scan/target data is engagement data governed by the customer's authorization scope,
> not covered here.

---

## 1. Data collected

| Data | Where stored | Purpose | Classification |
|------|--------------|---------|----------------|
| Email address | `users.email` | Login identity, account contact | PII |
| Full name | `users.full_name` | Display / attribution | PII |
| Password | `users.password_hash` | Authentication | Secret (hashed) |
| MFA TOTP secret | `users.mfa_secret_encrypted` | Second factor | Secret (encrypted) |
| MFA recovery codes | `mfa_recovery_codes.code_hash` | MFA account recovery | Secret (hashed) |
| Refresh tokens | `refresh_tokens.token_hash` | Session continuation | Secret (hashed) |
| API keys | `api_keys.key_hash` (+ non-secret `prefix`) | Programmatic access | Secret (hashed) |
| Login / usage timestamps | `users.last_login_at`, `api_keys.last_used_at` | Security & audit | Metadata |
| Audit actor | `audit_events.actor_user_id`, `actor_email` | Tamper-evident activity log | PII (denormalized) |

**Data minimization.** The AI layer records only token **counts** and estimated cost
(`ai_usage`); prompt and response **content is never persisted**. Application logs are
run through centralized redaction (see §2) so secrets and emails do not reach log sinks.

## 2. Encryption & protection

- **Passwords** — hashed with **bcrypt**; never logged, never returned by any endpoint.
- **MFA TOTP secret** — encrypted at rest with **Fernet** (AES-128-CBC + HMAC), the key
  derived from `MFA_ENCRYPTION_KEY`. Production startup refuses to boot without it.
- **Recovery codes / refresh tokens / API keys** — stored only as **SHA-256** hashes;
  the plaintext is shown exactly once and never recoverable.
- **Tenant isolation** — PostgreSQL **FORCE row-level security** (`workspace_isolation`)
  on tenant tables; the production DB role is non-superuser so RLS is enforced.
- **Secrets delivery** — secrets support the `<NAME>_FILE` convention (Docker Secrets /
  Vault); `validate_production()` blocks placeholder secrets, wildcard CORS, and disabled TLS.
- **Log redaction** — `apps/api/core/log_redaction.py` scrubs passwords, tokens, API
  keys, and email addresses from all log output (key-based drop + value masking),
  applied in the JSON and text formatters.

## 3. Retention

Operational data is purged by age via the retention subsystem
(`apps/api/retention`, default **disabled + dry-run**; see `core/config.py`):

| Data | Window (default) |
|------|------------------|
| Raw scan evidence | 90 days |
| Scan records | 180 days |
| AI usage/cost log | 180 days |
| Generated reports | 365 days |
| In-app notifications | 90 days |
| Expired refresh tokens | 7 days past expiry |
| Audit events | 730 days (compliance window) |

Credential material for an **active** account is retained for the life of the account;
erasure (§4) removes or anonymizes it immediately on request.

## 4. Deletion (right to erasure)

**Endpoint:** `DELETE /api/v1/users/me` — requires password confirmation; irreversible.

Because several foreign keys into `users` are `ON DELETE RESTRICT`
(workspace ownership, scans/projects/schedules) and the audit trail must survive,
erasure is performed by **crypto-shred / anonymization** rather than a row delete:

1. **Audit PII anonymized** — `audit_events.actor_email` is overwritten with `[deleted]`
   for the user, per-workspace under the RLS GUC. `actor_user_id` is preserved so the
   trail stays attributable to the (now anonymized) record.
2. **Credentials destroyed** — all refresh tokens and MFA recovery codes are deleted.
3. **API keys revoked** — every key the user created is revoked (unusable immediately).
4. **User row scrubbed** — email → per-id tombstone (`deleted+<id>@deleted.invalid`),
   name → `Deleted User`, password replaced with a fresh unguessable hash, MFA cleared,
   `status = "deleted"`.

After erasure the account cannot authenticate (status check + tombstoned email), and no
personal data remains beyond the non-PII audit skeleton.

**Known residual.** Audit events in a workspace the user has already left are anonymized
on the next retention pass (bounded by the 730-day audit window), because RLS scopes the
immediate anonymization to the user's current memberships.

## 5. Export (right of access & portability)

**Endpoint:** `GET /api/v1/users/me/export` — returns the authenticated user's personal
data as JSON (GDPR Art. 15/20):

- **profile** — id, email, full name, status, MFA state, created/last-login timestamps
- **workspaces** — memberships with role, invited/joined timestamps
- **api_keys** — metadata only (name, non-secret prefix, created/last-used, revoked)
- **scans** — scans the user **initiated** (id, workspace, type, status, timestamps) — metadata
  only; scan config, evidence, and tool output are never exported
- **reports** — reports the user **generated** (id, project, type, format, scan ids, timestamp) —
  the `storage_uri`/PDF bytes are never exported
- **audit_events** — events where the user was the **actor** (id, workspace, action, resource
  type/id, timestamp) — the free-text `detail` is excluded to avoid over-sharing
- **activity_summary** — workspace/API-key/scan/report/audit counts, last login

The export contains **metadata only**; password hashes, MFA secrets, token/key hashes, and
internal storage paths are structurally excluded and never serialized. Scans/reports/audit are
scoped to the user's **own** ownership and their **workspace memberships under RLS**, so a
data-subject export can never surface another tenant's data. The access itself is audited
(`account.exported`, counts only). Additive/back-compatible: the fields default to empty.

---

*Implementation references:* `apps/api/modules/users/service.py` (export + erasure),
`apps/api/modules/users/router.py` (endpoints), `apps/api/core/log_redaction.py`
(redaction), `apps/api/retention/` (retention). Tests: `test_account_erasure.py`,
`test_data_export.py`, `test_log_redaction.py`.
