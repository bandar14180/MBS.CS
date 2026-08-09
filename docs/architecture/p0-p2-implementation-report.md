# Implementation Report — P0/P1/P2 Hardening

Branch `feat/phase2-pentest-attack-mapping`. Resolves every P0 and P1 item from the
[backend issues report](backend-issues-report.md) and all P2 improvements.
Additive and backward-compatible; no architecture rewrite; existing behavior and
tests preserved. Detailed per-workstream notes + full env-var tables live in
[p0-p1-hardening.md](p0-p1-hardening.md).

**Result: 149 tests pass** (was 124). Single migration head `a7b8c9d0e1f2`
(unchanged — no schema changes this round). Commits: `1313252` (P0), `6dd27d8`
(P1), `7cda7ea` (P2).

## What changed

**P0 — blockers**
- **Local AI provider (Ollama)** behind the existing factory (`AI_PROVIDER=local`);
  reuses the OpenAI-compatible path; no agent changes; `/ai/status` gains a
  `reachable` probe. Removes external egress from the AI path.
- **Enterprise TLS/proxy**: custom CA bundle + proxy support for all outbound
  clients (httpx + Go tools); TLS verification never disabled by default (prod
  validated).
- **Evidence storage fail-soft**: object-storage outage no longer fails a scan —
  sentinel evidence, tool marked `partial`, scan `completed_with_errors`.
- **Unsupported target types** (`api`/`cloud_account`/`repo`) rejected at creation
  with a 400 instead of a hollow "successful" scan.

**P1 — security & reliability**
- **`/metrics`** secured via `METRICS_MODE` (disabled/token/authenticated/public),
  secure by default (fail closed).
- **Celery**: acks_late + reject_on_worker_lost, prefetch=1, named queues
  (`scans`/`default`), autoretry + exponential backoff, Redis DLQ, idempotent
  `run_scan`.
- **Async AI**: assistant/remediation/FP provider calls moved off the event loop
  (`run_in_threadpool`); response contract unchanged.
- **Rate limiting**: fixed-window → Redis sorted-set sliding window (fail-open).
- **Secrets**: documented loading order (env → `<NAME>_FILE` Docker/K8s → external
  backend); AWS Secrets Manager interface (lazy boto3).

**P2 — product improvements**
- In-process **event bus** (`ScanCompleted`); notification is now a subscriber
  (behavior identical).
- **StorageProvider** and **NotificationProvider** interfaces (S3/in-app wired;
  Azure/GCS/email/Slack/Teams/webhook stubbed behind the interface).
- **ATT&CK catalog** +16 CWEs / +19 tags / 4 new techniques.
- **CI** workflow (pytest + non-blocking scan-doctor).
- **httpx tech-detect model** baked at build (best-effort).

## Files modified / added
- **Config/core:** `core/config.py` (AI-local, TLS/proxy, metrics, supported target
  types, storage backend, secret order), `core/secrets.py` *(new)*,
  `core/events.py` *(new)*, `core/middleware.py` (sliding window), `main.py`
  (networking, secured `/metrics`).
- **AI providers:** `ai_agent/providers/local.py` *(new)*, `providers/_http.py`
  *(new)*, `providers/openrouter.py` + `factory.py`, `modules/assistant/router.py`
  (`reachable`), `modules/assistant/service.py` + `modules/vulnerabilities/ai_service.py`
  (threadpool).
- **Scanner/pipeline:** `scanner_engine/orchestrator.py` (evidence fail-soft,
  idempotency, event emit), `scanner_engine/storage_provider.py` *(new)*,
  `modules/scans/service.py` (target-type guard).
- **Celery:** `celery_app/worker.py` (reliability config), `celery_app/tasks/scan_tasks.py`
  (retry/backoff/DLQ), `infra/docker-compose.yml` (worker `-Q`).
- **Attack/notifications:** `modules/attack/catalog.py` (expanded),
  `modules/notifications/providers.py` *(new)*.
- **Infra/CI:** `infra/docker/Dockerfile.worker` (httpx warmup),
  `.github/workflows/ci.yml` *(new)*.
- **Docs:** `p0-p1-hardening.md` *(new)*, this report.

## Tests added
`test_metrics.py` (5), `test_reliability.py` (6), `test_interfaces.py` (6), plus
additions to `test_ai_providers.py` (local provider, TLS/verify, configure_networking),
`test_scans.py` (unsupported target type), `test_attack_mapping.py` (expanded
mappings). **+25 tests → 149 total.**

## New environment variables
AI: `AI_PROVIDER=local`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_API_KEY`.
TLS/proxy: `SSL_VERIFY`, `SSL_CA_BUNDLE`, `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`.
Scanner: `SUPPORTED_TARGET_TYPES`, `STORAGE_PROVIDER`.
Metrics: `METRICS_MODE`, `METRICS_TOKEN`.
Secrets: `SECRETS_BACKEND`, `AWS_SECRETS_ID`, `AWS_REGION`.
(Full table with defaults in [p0-p1-hardening.md](p0-p1-hardening.md).)

## Migration notes
No schema changes — Alembic head remains `a7b8c9d0e1f2`. Nothing to migrate.
`/metrics` is now **secure by default**: existing scrapers must set
`METRICS_TOKEN` (and send `X-Metrics-Token`) or set `METRICS_MODE=public` in dev.
The worker now runs with `-Q scans,default` (baked into compose).

## Performance impact
- Async AI offload frees the API event loop during AI calls (better concurrency
  under load); no change to individual response latency.
- Sliding-window rate limiting is 4 Redis ops/request (pipelined) vs 1–2 before —
  negligible, and only when `RATE_LIMIT_ENABLED=true`.
- httpx model bake removes a ~92 MB runtime download **when the build can fetch it**
  (see debt below).
- Local model: inference latency depends on the host GPU/CPU (trade external
  latency + cost for local compute).

## Security impact
- **Improved:** `/metrics` no longer leaks telemetry by default; TLS verification
  is enforced and configurable without ever defaulting off; secrets have a defined
  precedence with external-store support; the scan pipeline degrades instead of
  failing (availability). Local model keeps scan data in-house.
- **Neutral/among trade-offs:** the event bus carries live objects in-process (not
  serialized) — intentional for same-transaction subscribers.
- **Action required:** rotate the OpenRouter key pasted earlier; set `METRICS_TOKEN`
  in production.

## Remaining technical debt
- **httpx model bake is environment-dependent:** this build network intercepts TLS,
  so the build couldn't fetch the model and fell back to the runtime download. Works
  on a normal network / CI. Consider vendoring the model artifact for fully offline
  builds.
- **DLQ is a Redis list**, not a full dead-letter exchange; adequate for inspection
  + manual replay, not auto-replay.
- **Storage/notification interfaces** are wired for S3/in-app; Azure/GCS/email/Slack/
  Teams/webhook are stubs to be implemented.
- **`api`/`cloud_account`/`repo` scanning** is gated off (P0-4) until dedicated
  engines exist (roadmap T16/T17).
- **Async AI** uses a threadpool (non-blocking) rather than the full
  API→Celery→result job model, to preserve the synchronous response contract.
- **AWS Secrets Manager** is interface-only (boto3 not added as a dependency).
