# MBS.SC Backend — Full Codebase Audit (2026-07-31)

A fresh top-to-bottom audit of `apps/api` (11.2k LOC, 20 modules), independent of
the earlier issues report. It records **new findings** first, then confirms
residual debt already tracked. Severity: **HIGH / MED / LOW**.

Good news up front — the fundamentals are sound: no SQL string interpolation
(all `text()` uses bind params), no bare `except:`, no stray debug prints, no
hardcoded secrets, `.env` untracked. Passwords use bcrypt; JWT is HS256 with
algorithm pinning + a token-type check; refresh tokens and API keys are stored
only as SHA-256 hashes. RLS + RBAC are intact.

---

## NEW findings

### 1. SSRF / internal-target scanning — **HIGH**
Target `value` is an unvalidated string ([projects/schemas.py:38](apps/api/modules/projects/schemas.py#L38))
and [`_net.resolve_scan_host`](apps/api/scanner_engine/tool_runners/_net.py) accepts
**any** address — loopback, RFC1918, link-local, and `169.254.169.254` (cloud
metadata). Authorization-scope verification is **self-service** (the same tenant
submits *and* verifies with `authorization_scope:verify`, which owner/admin hold).
- **Impact:** a tenant can point a scan at internal infrastructure and have the
  worker scan it. In the current compose network that includes `postgres:5432`,
  `redis:6379`, `minio:9000`, the host metadata endpoint, and any reachable
  internal host — full internal port/vuln scanning via the platform.
- **Fix:** validate target values at creation and at resolution time — reject
  private/loopback/link-local/reserved/metadata ranges unless an explicit
  allowlist (`SCAN_ALLOW_PRIVATE_TARGETS`) is set; re-check the *resolved* IP in
  `resolve_scan_host` (defends DNS-rebinding too). Consider egress network
  policy on the worker as defense in depth.

### 2. No pagination on list endpoints — **MED**
`list_vulnerabilities`, `list_assets`, `list_scans`, `list_projects`,
`list_targets`, `list_reports`, `list_notifications` return **unbounded** result
sets (no `limit`/`offset`). Only `audit.list_events` caps (limit=100).
- **Impact:** memory blowup + slow responses on large workspaces; a cheap DoS
  vector; unbounded JSON payloads.
- **Fix:** add `limit`/`offset` (or keyset) params with sane caps across list
  services + routers.

### 3. Failing test: provider-coupled `test_use_ai_planner_without_key_is_rejected` — **MED**
[test_scans.py](apps/api/tests/test_scans.py) currently **fails** because the
running `.env` was set to `AI_PROVIDER=local` (for the local-model demo) and the
local provider is always "AI-enabled" (no key required), so the "no key → 400"
path isn't taken. The test monkeypatches only the openrouter/anthropic keys, not
`ai_provider` — same ambient-env coupling that was fixed for the assistant test.
- **Impact:** suite is red (148/149) whenever `AI_PROVIDER=local`.
- **Fix:** `monkeypatch.setattr(get_settings(), "ai_provider", "openrouter")` in the
  test so it is deterministic regardless of environment.

### 4. No `.dockerignore` — **LOW–MED**
Build context is the repo root (`context: ..`); with no `.dockerignore`, `.env`,
`.git`, and any `node_modules` are shipped to the Docker daemon on every build.
No secret is baked (Dockerfiles COPY only `apps/…`), but it is a hardening gap and
bloats/slows builds.
- **Fix:** add `.dockerignore` (`.env`, `.git`, `**/__pycache__`, `node_modules`,
  `docs`, `*.md`, plan files).

### 5. passlib 1.7.4 + bcrypt 4.x incompatibility warning — **LOW**
`passlib==1.7.4` (last released 2020, effectively unmaintained) can't read
`bcrypt==4.0.1`'s version, emitting a trapped error at startup. Hashing still
works, but the pin is stale.
- **Fix:** move to `bcrypt` directly (or `argon2-cffi`) for hashing, or pin a
  compatible pair; add a dependency-refresh + `pip-audit` step (see #6).

### 6. Dependency freshness / no vuln scanning — **LOW–MED**
Pins are ~mid-2024 (`fastapi 0.115.0`, `httpx 0.27.2`, `anthropic 0.34.2`,
`sqlalchemy 2.0.35`, …). No critical CVE stood out, but there is no automated
dependency audit.
- **Fix:** add `pip-audit`/Dependabot to CI (the new `.github/workflows/ci.yml` is
  the place) and schedule periodic refreshes.

### 7. Rate limiting off by default — **LOW** (config)
`RATE_LIMIT_ENABLED=false` by default (correct for dev/tests), so a default/prod
deploy that forgets to enable it has no throttling. The sliding-window limiter
exists (P1-8) but must be turned on.
- **Fix:** enable + tune in the production overlay; document in the go-live checklist.

### 8. Dead `scanner_engine/sandbox/` directory — **LOW**
Empty placeholder dir (no `__init__.py`, no files).
- **Fix:** remove it, or implement the intended sandboxing and document it.

---

## Confirmed residual debt (from prior work, by design)

- **Findings pipeline still largely inline** in `orchestrator._run_single_tool`
  (evidence→asset→vuln→risk→compliance→attack). The event bus (P2-10) adds a seam
  but the stages aren't extracted yet (roadmap T6).
- **Storage/notification interfaces are partial:** S3/in-app wired;
  `reports/storage.py` still imports evidence_store's **private**
  `_get_s3_client`/`_ensure_bucket`; Azure/GCS/email/Slack/Teams/webhook are stubs.
- **Cloud/API/repo scanning gated off** (P0-4) — no engines yet (T16/T17).
- **DLQ is a Redis list** (inspection/manual replay, not auto-replay).
- **AWS Secrets Manager** integration is interface-level (boto3 is present, but
  untested against real AWS).
- **Access-token revocation window** ~15 min (stateless JWT) — accepted trade-off.
- **httpx tech-detect model bake** is best-effort; blocked on TLS-intercepting
  build networks → runtime download fallback.
- **AI-dominated scan latency:** the correlator runs at end of scan; on the local
  3B model it added ~2.5 min for 20 findings. Consider a size/latency budget or a
  faster model for large scans.

---

## Current state
- Tests: **148 passing, 1 failing** (finding #3 — environment-coupled, not a code
  regression; green again with `AI_PROVIDER=openrouter` or the one-line test fix).
- Migration head: single, `a7b8c9d0e1f2`.
- P0/P1 from the prior report are resolved; P2 delivered as additive interfaces.

## Suggested priority
1. **#1 SSRF guard** (security-critical for a hosted/multi-tenant deployment).
2. **#3 fix the failing test**, then **#2 pagination**.
3. **#4 `.dockerignore`**, **#6 dependency audit in CI**, **#7 enable rate limiting** for go-live.
4. Cleanups (#5, #8) and the residual-debt items as roadmap allows.
