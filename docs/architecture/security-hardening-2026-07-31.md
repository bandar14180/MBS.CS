# Security & Production Hardening (2026-07-31)

Resolves every finding from [codebase-audit-2026-07-31.md](codebase-audit-2026-07-31.md)
plus residual debt. Additive and backward compatible; RLS/RBAC and existing APIs
preserved. Test suite: **206 passing, 0 failing**, environment-independent.

> Build note: this workstation's network intercepts TLS, so a *fresh* `pip install`
> (changed `requirements.txt`) can't reach PyPI here. Code is verified by running
> the suite with the source bind-mounted into the cached image; CI / normal
> networks build the images cleanly. TLS verification is never disabled to work
> around this.

---

## SSRF / internal-target protection (`scanner_engine/net_guard.py`)

Independent of the (self-service) authorization scope, addresses are validated at
**two layers**:

1. **Target creation** (`projects.create_target`) — rejects a literal or hostname
   that is / resolves to a forbidden address with **400**.
2. **Scan time** (`resolve_scan_host` → `resolve_and_validate`, plus an orchestrator
   pre-flight) — resolves **every** A/AAAA record and rejects if **any** is
   forbidden, then hands a validated address to the tool. Re-resolving at scan
   time is the **DNS-rebinding** defense (creation-time DNS is not trusted).

**Blocked by default:** loopback (`127/8`, `::1`), RFC1918 (`10/8`, `172.16/12`,
`192.168/16`), link-local (`169.254/16`, `fe80::/10`), IPv6 ULA (`fc00::/7`),
unspecified (`0.0.0.0`, `::`), multicast, reserved, and cloud-metadata endpoints
(`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`). IPv4-mapped IPv6
(`::ffff:10.0.0.1`) is normalized so it can't smuggle a private address; scheme /
port / path / userinfo are stripped before parsing.

**Allowing internal ranges (on-prem only):**
```
SCAN_ALLOW_PRIVATE_TARGETS=true
SCAN_ALLOWED_CIDRS=10.20.0.0/16,192.168.50.0/24
```
Only addresses inside `SCAN_ALLOWED_CIDRS` become scannable. Cloud-metadata IPs
stay blocked unless listed as an explicit single host (`/32` or `/128`). There is
**no blanket "disable SSRF" switch.** Defense in depth: also restrict worker egress
at the network layer. Coverage: 37 tests in `test_net_guard.py`.

## Scanner capability model (`scanner_engine/capabilities.py`)
Code (not config) is the source of truth for scannable target types (`domain`,
`ip_range` today). `create_scan` rejects `api`/`cloud_account`/`repo` with a **400**
(no hollow scans); `SUPPORTED_TARGET_TYPES` can narrow but never widen beyond an
implemented engine. `GET /api/v1/scan-capabilities` exposes the map. Future engines
plug in here.

## Pagination (`core/pagination.py`)
Every list endpoint (vulnerabilities, scans, assets, projects, targets, reports,
notifications, audit) takes `limit` (1..200, default 50) + `offset` (≥0),
FastAPI-validated (negative/huge → 422). **Backward compatible:** bodies stay bare
arrays; `X-Total-Count` / `X-Limit` / `X-Offset` / `X-Has-More` come as headers.
Deterministic `ORDER BY` (with an id tiebreaker); one `COUNT` per list, no N+1.

## Rate limiting (production-safe)
Redis sliding-window limiter, path-aware, fail-open, env-driven. `validate_production()`
**refuses to boot** if `RATE_LIMIT_ENABLED` is false (or `METRICS_MODE=public`) in
production. Enabled in `docker-compose.prod.yml`.

## Metrics security
`METRICS_MODE`: `disabled` | `token` (require `X-Metrics-Token` == `METRICS_TOKEN`,
constant-time) | `authenticated` (bearer JWT) | `public` (dev). Secure by default
(fail-closed); prod overlay delivers `METRICS_TOKEN` via a Docker secret.

## Password hashing
`core/security.py` uses **bcrypt directly** (72-byte-safe), removing the stale
passlib 1.7.4 and its bcrypt-4.x startup warning. Existing `$2b$` hashes still
verify (compat test). Algorithm: bcrypt, 12 rounds.

## Secret management (`core/secrets.py`)
Loading order (first present wins): (1) explicit env / Docker-K8s injected env,
(2) `<NAME>_FILE` files (Docker Secrets `/run/secrets/*`, K8s mounts, Vault
templated), (3) external backend via `SECRETS_BACKEND` (AWS Secrets Manager;
lazy boto3). All setdefault, so explicit env wins. Nothing logs/hardcodes secrets.
Mock-tested (no real AWS needed).

## Container hardening
`.dockerignore` keeps `.env`, `.git`, docs, caches, `node_modules` out of the build
context (nothing is COPYed in — verified: no secret in the image/context). Non-root
`appuser`; healthcheck; no `--reload` in prod images.

## Dependency auditing
CI runs `pip-audit -r apps/api/requirements.txt` (non-blocking: triage/pin rather
than wedge PRs). Refresh dependencies periodically.

## Celery DLQ (`celery_app/dlq.py`)
Exhausted scan tasks land on Redis list `dlq:scans.run_scan` with a structured
entry `{task_name, task_id, scan_id, retries, error, ts}` (workspace derivable via
the scan). Operator CLI:
```
python -m apps.api.celery_app.dlq list          # inspect
python -m apps.api.celery_app.dlq replay <scan_id>   # idempotent re-enqueue + remove
python -m apps.api.celery_app.dlq remove <scan_id>
python -m apps.api.celery_app.dlq purge
```
Replay is idempotent (the orchestrator skips terminal scans) and never auto-loops.

## Storage & notification interfaces
`StorageProvider` (S3/MinIO implemented; Azure/GCS raise `NotImplementedError`);
`reports/storage.py` no longer imports evidence_store internals — it goes through
the interface. `NotificationProvider` (in-app implemented; email/Slack/Teams/webhook
raise `NotImplementedError` — never silent success).

## AI correlator latency controls
All fail-soft; the **deterministic** ATT&CK/kill-chain mapping is always produced
regardless:
- `AI_CORRELATOR_MAX_FINDINGS` (default 60) — skip the AI narrative on very large
  scans.
- `AI_CORRELATOR_TIMEOUT_SECONDS` (default 90) — wall-clock bound; a timeout falls
  back to deterministic. **Local/slow models (e.g. Ollama 3B) need a higher value**
  (set ~300).
- `AI_CORRELATOR_MODEL` — optional smaller/faster model for the correlator.
The `/scans/{id}/kill-chain` endpoint returns `ai_generated:false` when the AI
narrative was skipped/timed-out/failed (e.g. a small local model returns invalid
JSON) — the kill chain is still served from the deterministic mapping.

## httpx tech-detection model
`Dockerfile.worker` warms the ~92 MB "dit" model at build (best-effort, `|| true`);
if the build network can't fetch it, scans download it once at runtime (unchanged
fallback). No insecure TLS bypass.

---

## Production go-live checklist

Startup (`validate_production()`) hard-fails if any of these are wrong, but verify:

- [ ] `ENVIRONMENT=production`
- [ ] Real `JWT_SECRET_KEY` (not `change-me-*`), S3 creds (not `minioadmin`), DB creds (not `mbs:mbs`) — via `*_FILE` / secret store
- [ ] `TRUSTED_HOSTS` and `CORS_ALLOW_ORIGINS` explicit (no wildcards)
- [ ] `RATE_LIMIT_ENABLED=true` (+ tuned `RATE_LIMIT_*`)
- [ ] `METRICS_MODE=token` (or `authenticated`) + `METRICS_TOKEN` set; never `public`
- [ ] `ENABLE_HSTS=true` (behind TLS)
- [ ] `SSL_VERIFY=true`; set `SSL_CA_BUNDLE` / `HTTPS_PROXY` if the network requires
- [ ] `SCAN_ALLOW_PRIVATE_TARGETS=false` unless an on-prem engagement needs it (then set `SCAN_ALLOWED_CIDRS`); restrict worker egress at the network layer
- [ ] AI: rotate any exposed key; for private/offline use `AI_PROVIDER=local` (Ollama) and raise `AI_CORRELATOR_TIMEOUT_SECONDS`
- [ ] Backups (pg_dump + object store) scheduled; DLQ monitored (`dlq:scans.run_scan`)
- [ ] CI green: tests + `pip-audit` + scan-doctor

## New environment variables (this workstream)
`SCAN_ALLOW_PRIVATE_TARGETS`, `SCAN_ALLOWED_CIDRS`, `AI_CORRELATOR_MAX_FINDINGS`,
`AI_CORRELATOR_TIMEOUT_SECONDS`, `AI_CORRELATOR_MODEL`. (Earlier: `METRICS_MODE`,
`METRICS_TOKEN`, `STORAGE_PROVIDER`, `SSL_*`, `HTTP(S)_PROXY`, `SUPPORTED_TARGET_TYPES`,
`SECRETS_BACKEND`/`AWS_SECRETS_ID`/`AWS_REGION`, `OLLAMA_*`.)
