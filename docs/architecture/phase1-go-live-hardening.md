# Phase 1 — Go-Live Hardening (Review & Acceptance Mapping)

Branch: `feat/phase1-go-live-hardening` (off `master`).
Status as of this review: **code complete and test-verified**; one acceptance
item (live-AI smoke test) is blocked pending a rotated OpenRouter key.

This document is the Task 20 (review / acceptance) mapping for Phase 1. It maps
each brief task and each item in the roadmap's Verification section to the
concrete change that delivers it and how it was verified.

## Scope

Phase 1 covers the go-live subset of the 20-task brief: **Task 3** (secrets),
**Task 4** (security edge), **Task 1** (live AI via OpenRouter + usage logging),
**Task 12** (observability basics), Docker hardening, and seeds for **Task 2**
(provider factory) and **Task 15** (AI usage/cost row). Everything is additive:
no feature removed, no working module rewritten, no breaking API change, no
existing schema altered. `apps.api.main:app` is preserved as the import path.

## Task → delivery map

| Task | Delivered by | Notes |
|------|--------------|-------|
| **T3 — Secrets / config validation** | `apps/api/core/config.py`: new AI/security/logging settings; `_resolve_file_secrets()` (`<NAME>_FILE` → Docker Secrets/Vault seam); `validate_production()` fail-fast on placeholder secrets, `mbs:mbs` DB creds, `minioadmin`, wildcard CORS/hosts, unknown provider. | No Vault dependency added — env-var + `_FILE` indirection only. No-op outside production. |
| **T4 — Security edge** | `apps/api/core/middleware.py`: `SecurityHeadersMiddleware` (nosniff / DENY / no-referrer / CSP, opt-in HSTS), `RateLimitMiddleware` (Redis fixed-window, path-aware auth/AI buckets, **fail-open**). `TrustedHostMiddleware` + tightened prod CORS in `main.py`. | Rate limiting off by default (dev/tests never throttled); enable via `RATE_LIMIT_ENABLED`. |
| **T1 — Live AI + usage logging** | `apps/api/ai_agent/providers/` (`base`, `openrouter` primary, `anthropic` alternate, `factory`, `usage`); retry+timeout+cost+token capture; 5 agents default to `get_ai_client()`; provider-aware `/ai/status`. `claude_client.py` kept as a back-compat shim. | Business logic depends only on `SupportsComplete`. `AIProviderError` subclasses `RuntimeError` to preserve the fail-loud/fail-soft contract. |
| **T12 — Observability** | `core/logging.py` (hand-rolled JSON formatter), `core/observability.py` (correlation-id contextvar + Prometheus metrics, guarded import), `ObservabilityMiddleware`, `/ready` (DB+Redis), `/metrics`. | Correlation id read from / echoed in `X-Request-ID`. |
| **T2 — Provider factory (seed)** | `providers/factory.get_ai_client()` selects on `ai_provider`; OpenRouter + Anthropic adapters in place. | Remaining adapters (openai/gemini/local) are Phase 2. |
| **T15 — Cost tracking (seed)** | `ai_usage` table (migration `f1a2b3c4d5e6`, FORCE RLS), `AIUsageRow` model, `usage_repo.persist_ai_usage()` (independent tx). Wired into assistant + planner paths. | Full per-workspace cost rollups are Phase 2. |
| **Docker hardening** | `Dockerfile.api` / `Dockerfile.worker` non-root + healthcheck + prod CMD (no `--reload`); base compose prod-safe; `docker-compose.override.yml` (dev reload) + `docker-compose.prod.yml` (Docker Secrets). | API container verified running as `appuser` (uid 10001), health `healthy`. |

New dependency added: **`prometheus-client==0.21.0`** only. The roadmap
originally named `slowapi` and `structlog`; both were avoided by reusing the
existing `redis`/`httpx` deps and hand-rolling the JSON log formatter and the
Redis rate limiter. This keeps the dependency surface minimal.

## Verification results

| # | Item | Result |
|---|------|--------|
| 1 | Full pytest suite green + new provider/validation unit tests | **PASS** — 112 passed (102 existing + 10 new in `test_ai_providers.py`), 0 failures. Run in the api container against the migrated Postgres service. |
| 2 | Live AI smoke test (real key → `/ai/status` + Assistant `/ask` returns an answer + an `ai_usage` row) | **BLOCKED** — requires a valid OpenRouter key. The previously pasted key is treated as compromised and must be rotated first; it is deliberately **not** present in this environment's `.env` (`/ai/status` reports `enabled:false`), so no accidental paid calls are possible. |
| 3 | Graceful degradation (no key → 503, not a crash) | **PASS** — `POST /ask` with no key returns HTTP **503** with a clear provider-aware message; the fail-soft chain (`AIProviderError`→`RuntimeError`→503) works end-to-end. Planner path 400 covered by `test_scans.py`. |
| 4 | Security edge (headers present; TrustedHost) | **PASS** — responses carry `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`. TrustedHost is permissive in dev (`['*']`); `validate_production()` forces explicit hosts in production. |
| 5 | Startup validation (prod + placeholder secrets → fail fast; real secrets → boots) | **PASS** — covered by `test_validate_production_rejects_dev_defaults` / `_accepts_hardened_config` / `_noop_in_dev`. |
| 6 | Observability (`/ready`, `/metrics`, JSON logs + correlation id) | **PASS** — `/ready` → 200 `{database:ok, redis:ok}`; `/metrics` exposes http/AI/scan counters; `X-Request-ID` generated when absent and echoed back when supplied. |
| 7 | Docker (non-root, no `--reload`, healthcheck) | **PASS** — container runs as `appuser` (uid 10001); prod CMD is multi-worker uvicorn with no `--reload`; healthcheck reports `healthy`. |

## Backward compatibility

- Only additive API changes: `/ai/status` gains a `provider` field; new `/ready`
  and `/metrics` endpoints. No path/response shape changed. `apps.api.main:app`
  import path preserved.
- Existing schemas untouched; only the new `ai_usage` table is added
  (single linear Alembic chain: `e6a8c0d2f248` → `f1a2b3c4d5e6`).
- Agents still accept injected `SupportsComplete` fakes → existing tests
  unaffected.

## Follow-ups before go-live

1. **Rotate the OpenRouter API key** at openrouter.ai (the earlier plaintext key
   is compromised) and place it only in env / the secret store — never in the
   repo. Then run acceptance item #2 (live-AI smoke test).
2. Set production env: real `JWT_SECRET_KEY`, S3 creds, DB creds, explicit
   `TRUSTED_HOSTS` and `CORS_ALLOW_ORIGINS`, `ENABLE_HSTS=true` (behind TLS),
   `RATE_LIMIT_ENABLED=true`. `validate_production()` will refuse to boot
   otherwise.

## Known production risks (tracked for later phases)

- AI provider calls are synchronous inside async handlers (pre-existing) — fine
  in Celery workers; revisit async providers in Phase 2.
- OpenRouter is a third-party dependency in the AI path; the retry/timeout/
  degradation wrapper mitigates but availability/cost now depend on its uptime.
- Rate limiting is per-process unless Redis-backed — it uses the Redis backend
  for multi-worker correctness.
- Secret rotation is enabled (env/`_FILE`) but not automated until Vault (Phase 5+).
