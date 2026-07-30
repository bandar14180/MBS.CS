# P0/P1 Hardening — Implementation Notes

Follow-on to the [backend issues report](backend-issues-report.md). Additive,
backward-compatible; no architecture rewrite. This document is updated per
workstream and lists new environment variables + behavior.

---

## P0 — Blockers (done)

### P0-1 Local AI provider (Ollama)
- New `ai_agent/providers/local.py` (`LocalClient`) — an OpenAI-compatible
  provider that reuses the OpenRouter HTTP path (subclass); only base URL / model
  / auth differ. Ollama needs no key (a dummy is sent and ignored).
- Selected by `AI_PROVIDER=local`; no agent changes (still `SupportsComplete`).
- `/ai/status` gains an additive `reachable` field: for the local provider it
  probes the model server (`GET {base}/models`, off the event loop, fail-soft).
- Keeps scan data in-house and needs **no external egress** — the fix for
  networks that block the internet or intercept TLS.

### P0-2 Enterprise TLS / proxy support
- New `ai_agent/providers/_http.py::sync_client()` builds every provider's
  httpx client honoring a custom CA bundle / verification toggle. OpenRouter (and
  the local provider via inheritance) now use it.
- `core/config.configure_networking()` mirrors proxy + CA settings into the
  process env so httpx (`trust_env`) **and** the Go scanner tools honor them.
  Called from the app lifespan and the Celery scan task.
- **TLS verification is never disabled by default.** A custom CA bundle is the
  correct fix for TLS-inspecting proxies. `validate_production()` refuses to boot
  if `SSL_VERIFY` is off in production.

### P0-3 Evidence storage fail-soft
- `orchestrator._run_single_tool` wraps `evidence_store.store_raw_output` in
  try/except. On a storage outage it records a **sentinel** evidence row (so
  vulnerability→evidence linkage still holds), notes the failure on the tool run,
  and downgrades that tool from `completed` → `partial`, so the scan aggregates to
  `completed_with_errors` instead of failing. Object-storage downtime no longer
  fails otherwise-successful scans.

### P0-4 Unsupported target types rejected
- `create_scan` validates the target type against `SUPPORTED_TARGET_TYPES`
  (default `domain,ip_range`) and returns a clear **400** for `api` /
  `cloud_account` / `repo` targets, which have no scanner engine yet — never a
  "completed" scan that assessed nothing.

---

## New environment variables (P0)

| Variable | Default | Purpose |
|----------|---------|---------|
| `AI_PROVIDER` | `openrouter` | now also accepts `local` (Ollama/vLLM) |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | local model OpenAI-compatible endpoint (use `http://host.docker.internal:11434/v1` from a container) |
| `OLLAMA_MODEL` | `llama3.1:8b` | local model id |
| `OLLAMA_API_KEY` | `` | optional; Ollama ignores auth |
| `SSL_VERIFY` | `true` | **dev-only** override; keep `true` in prod (validated) |
| `SSL_CA_BUNDLE` | `` | path to a custom CA bundle (corporate root, PEM) |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | `` | egress proxy; mirrored to env for httpx + tools |
| `SUPPORTED_TARGET_TYPES` | `["domain","ip_range"]` | target types allowed to scan |

`REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` set in the environment are also honored by
`httpx_verify` as a fallback CA source.

### Using a local model (recommended for private / offline / TLS-restricted networks)
```
AI_PROVIDER=local
OLLAMA_BASE_URL=http://host.docker.internal:11434/v1
OLLAMA_MODEL=llama3.1:8b
```
Run `ollama serve` + `ollama pull llama3.1:8b` on the host. No external egress; no
API key; no TLS-interception problem.

## Tests (P0)
`tests/test_ai_providers.py`: local provider reuses the OpenAI-compatible path,
factory selects local, local enables AI without a key, `httpx_verify` reflects
settings, `validate_production` rejects disabled SSL, `configure_networking`
mirrors env. `tests/test_scans.py`: unsupported target type → 400.

---

## P1 — Security & reliability (done)

### P1-5 Secure `/metrics`
- `main.py` `/metrics` now enforces `METRICS_MODE` (secure by default):
  `disabled` (404) | `token` (require `X-Metrics-Token` == `METRICS_TOKEN`,
  constant-time) | `authenticated` (valid bearer JWT) | `public` (dev). In `token`
  mode with no token set, access is denied (fail closed).

### P1-6 Celery reliability
- `celery_app/worker.py`: `task_acks_late` + `task_reject_on_worker_lost` (a task
  killed mid-scan is re-delivered), `worker_prefetch_multiplier=1`, named queues
  via `task_routes` (`scans.run_scan` → `scans`; everything else → `default`).
- `scan_tasks.run_scan_task`: `autoretry_for=(Exception,)` with exponential
  backoff (`retry_backoff`, max 300s, jitter), `max_retries=3`; on exhaustion the
  task is **dead-lettered** to the Redis list `dlq:scans.run_scan` (best-effort).
- **Idempotency:** `orchestrator.run_scan` returns early if the scan already
  reached a terminal state, so acks_late redelivery never re-runs a finished scan.
- The worker service consumes `-Q scans,default`.

### P1-7 Async AI (non-blocking)
- The synchronous provider calls in the API process (assistant `ask`, remediation
  `generate`, FP `analysis`) now run via `run_in_threadpool`, off the event loop.
  Response shape is unchanged (no breaking change); usage collection still works
  (the context is copied into the worker thread). The planner/correlator already
  run in Celery.

### P1-8 Sliding-window rate limiting
- `core/middleware.RateLimitMiddleware` replaced the fixed-window counter with a
  Redis **sorted-set sliding window** (drop-old / add / count), smoothing the
  boundary burst a fixed window allows. Still path-aware, env-driven, and
  fail-open.

### P1-9 Secret management
- New `core/secrets.py`: pluggable secret loading with a documented order —
  (1) explicit env (incl. Docker/K8s injected env), (2) `<NAME>_FILE` files
  (Docker Secrets `/run/secrets/*`, K8s mounted secrets, Vault templated files),
  (3) an external backend via `SECRETS_BACKEND` (AWS Secrets Manager provided as
  an interface; boto3 imported lazily, only when selected). `get_settings()` runs
  the external backend then the file resolver; both use setdefault so explicit env
  always wins. Nothing hardcodes/logs secrets.

## New environment variables (P1)

| Variable | Default | Purpose |
|----------|---------|---------|
| `METRICS_MODE` | `token` | `disabled` \| `token` \| `authenticated` \| `public` |
| `METRICS_TOKEN` | `` | shared token for `token` mode (fail-closed if unset) |
| `SECRETS_BACKEND` | `` | `aws` selects AWS Secrets Manager (else none) |
| `AWS_SECRETS_ID` | `` | secret bundle id when `SECRETS_BACKEND=aws` |
| `AWS_REGION` | `` | region for AWS Secrets Manager |

Rate-limit vars (`RATE_LIMIT_ENABLED`, `RATE_LIMIT_DEFAULT`, `RATE_LIMIT_AUTH`,
`RATE_LIMIT_AI`) are unchanged; the strategy under them is now sliding-window.

## Tests
`test_metrics.py` (all 4 modes), `test_reliability.py` (secret order + AWS provider
mapping + Celery retry/queue config + best-effort DLQ), plus the P0 tests. Full
suite: **142 passed**.

## DLQ operations
Failed scans that exhaust retries land on the Redis list `dlq:scans.run_scan`
(JSON: `scan_id`, `error`, `ts`), capped at 1000. Inspect with
`redis-cli LRANGE dlq:scans.run_scan 0 -1`.

---

## P2 — Product improvements (done)

All additive; existing behavior preserved.

### P2-10 Event-driven findings pipeline
- `core/events.py`: a tiny in-process event bus (`subscribe` / `emit`, sync+async
  handlers, best-effort — a failing subscriber is logged and skipped). Domain
  event `ScanCompleted`.
- The orchestrator now emits `ScanCompleted` on terminal status; the in-app
  notification is registered as the first subscriber and does **exactly** what the
  previous direct call did (behavior unchanged). New reactions can subscribe
  without touching the orchestrator.

### P2-11 Storage provider interface
- `scanner_engine/storage_provider.py`: `StorageProvider` ABC + `S3StorageProvider`
  (MinIO/S3, reuses the existing evidence_store client helpers) + `get_storage_provider()`
  selected by `STORAGE_PROVIDER`. Azure Blob / GCS raise a clear NotImplemented
  behind the same interface. `evidence_store` itself is unchanged.

### P2-12 Notification provider interface
- `modules/notifications/providers.py`: `NotificationProvider` ABC +
  `InAppNotificationProvider` (wraps the existing `create_notification`) +
  placeholders for email/slack/teams/webhook that raise NotImplemented, via
  `get_notification_provider(channel)`. In-app stays the wired default.

### P2-13 Expanded ATT&CK catalog
- `modules/attack/catalog.py`: +16 CWE mappings (CSRF, clickjacking, open redirect,
  file upload, XXE, deserialization, access control, weak crypto/cleartext, DoS, …)
  and +19 nuclei-tag mappings, plus new techniques (T1040 Network Sniffing, T1187
  Forced Authentication, T1499 Endpoint DoS, T1140). Deterministic mapping
  unchanged.

### P2-14 CI
- `.github/workflows/ci.yml`: a `tests` job (Postgres+Redis services → migrations →
  pytest) and a non-blocking `scan-doctor` job that builds the worker image and
  runs `python -m apps.api.scanner_engine.doctor`.

### P2-15 httpx tech-detection model baked in
- `Dockerfile.worker` warms httpx's ~92 MB "dit" model at build time (best-effort,
  `|| true`) so scans don't download it at runtime; falls back to the runtime
  download if the build network can't fetch it.

## New environment variables (P2)

| Variable | Default | Purpose |
|----------|---------|---------|
| `STORAGE_PROVIDER` | `s3` | object-storage backend (`s3`/`minio`; azure_blob/gcs planned) |

## Tests (P2)
`test_interfaces.py` (event bus dispatch + failure isolation + async handlers;
storage factory default/unknown; notification factory + unimplemented channel),
`test_attack_mapping.py` (expanded-catalog mappings). Full suite: **149 passed**.
