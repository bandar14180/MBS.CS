# MBS.SC Backend — Outstanding Issues Report

_Compiled 2026-07-29 from the Phase 1/Phase 2 work and a full live end-to-end scan
(scanme.nmap.org). Each item lists impact and a recommended fix. Priorities:
**P0** = blocks correct/complete operation, **P1** = important hardening/reliability,
**P2** = roadmap / extensibility / product completeness._

Context: the platform is a FastAPI modular monolith + Celery workers + Postgres
(RLS) + MinIO + an AI agent layer. Phases 1–2 are done (go-live hardening; tool
reliability + MITRE ATT&CK / kill-chain). The items below are what remains.

---

## P0 — Confirmed blockers / correctness

### 1. AI provider egress fails under TLS interception; no way to trust a custom CA
- **Observed:** during the live scan the AI Correlator narrative failed with
  `SSL: CERTIFICATE_VERIFY_FAILED (unable to get local issuer certificate)`, and
  the **API container reproduces the same failure** — so it is network-wide, not
  worker-specific. The host is doing TLS inspection (proxy/VPN/AV) with a root CA
  that neither the system bundle nor `certifi` trusts.
- **Impact:** every live-AI feature (planner, assistant, remediation, FP reducer,
  attack narrative) silently degrades whenever the network intercepts TLS. Today
  the app has no way to (a) trust a corporate root CA, (b) honor an HTTPS proxy,
  or (c) fall back to a local model.
- **Fix:** add settings for a custom CA bundle (`REQUESTS_CA_BUNDLE`/
  `SSL_CERT_FILE` passthrough + an httpx `verify=` hook in the providers) and
  proxy support; **and/or** ship the local (Ollama/vLLM) provider adapter so the
  AI path needs no external egress at all. The fail-soft design worked correctly
  here (scan completed, deterministic kill-chain returned) — this is about
  restoring the AI layer, not preventing a crash.

### 2. Object storage (MinIO/S3) is a hard single point of failure for every scan
- **Where:** `scanner_engine/orchestrator.py::_run_single_tool` calls
  `evidence_store.store_raw_output(...)` **outside** the resilient try/except.
- **Impact:** if MinIO/S3 is unavailable, the exception propagates and the whole
  scan fails — even though the tools themselves ran fine. Storage downtime = zero
  successful scans.
- **Fix:** wrap evidence storage in the same resilient handling (record the tool
  run as `partial`/`failed` with the error, keep going), and/or add a retry +
  local-disk fallback for the evidence blob.

### 3. Non-scannable target types silently "succeed" with no tools
- **Where:** `TargetCreate` accepts `domain | ip_range | api | cloud_account |
  repo`, but `TOOL_REGISTRY` only has web/network recon tools
  (subfinder/httpx/naabu/nmap/nuclei). For `api`, `cloud_account`, `repo` targets
  no runner applies (or they run against a non-host value and fail), so the scan
  "completes" having done nothing.
- **Impact:** the product accepts targets it cannot actually assess — a
  correctness/honesty gap.
- **Fix:** either build runners for those types (see P2 items 14/15/16) or
  reject/feature-flag those target types at creation until supported.

---

## P1 — Security & reliability hardening

### 4. `/metrics` is unauthenticated and publicly exposed
- **Where:** `main.py` registers `GET /metrics` with no auth dependency.
- **Impact:** leaks internal telemetry (route templates, request counts, AI spend
  in USD, scan outcomes) to anyone who can reach the port.
- **Fix:** network-restrict it (bind to an internal interface / scrape via the
  compose network only) or gate it behind an auth/permission check.

### 5. Celery has no retry/DLQ/queue policy
- **Impact:** a worker crash mid-scan loses the task; a poison task can wedge a
  worker; there are no named queues/`task_routes`, no `acks_late`, no idempotency
  keys, no dead-letter path. (Cancellation is fine — `cancel_scan` revokes with
  `terminate=True`.)
- **Fix:** retry-with-backoff + `acks_late` + `task_routes` (separate scan / AI /
  beat queues) + a DLQ and idempotency keys (roadmap T14).

### 6. Synchronous AI calls inside async request handlers
- **Where:** assistant / remediation / FP paths call the provider synchronously in
  an async endpoint.
- **Impact:** heavy AI use on the API process can block the event loop (fine in
  Celery workers). **Note:** this is also why item 1's SSL error stalled for a
  full retry cycle inline.
- **Fix:** async provider clients, or offload these to Celery like the planner.

### 7. Rate limiting is coarse and off by default
- **Where:** `core/middleware.py` Redis **fixed-window** limiter,
  `RATE_LIMIT_ENABLED=false` by default.
- **Impact:** fixed windows allow ~2x burst at window boundaries; disabled means
  no protection in dev/default.
- **Fix:** enable in production, tune limits, consider sliding-window/token-bucket.

### 8. Secret management is manual
- **Impact:** secrets live in `.env` (plaintext, gitignored). The OpenRouter API
  key was pasted in chat and must be **rotated**. No automated rotation.
- **Fix:** the `<NAME>_FILE` seam is in place for Docker Secrets/Vault — wire an
  actual secret store for production; rotate the exposed key now.

### 9. Access-token revocation window
- **Status:** refresh tokens ARE revocable (logout sets `revoked_at`); access
  tokens (JWT HS256, 15-min TTL) are stateless and valid until expiry.
- **Impact:** a compromised access token can't be killed for up to 15 min.
  Acceptable for most cases; note it for high-assurance deployments.
- **Fix (optional):** short TTL + a jti denylist if instant revocation is needed.

### 10. No backups / disaster recovery
- **Impact:** no `pg_dump` or MinIO backup jobs, no retention policy, no documented
  recovery runbook (roadmap T13).
- **Fix:** scheduled DB + object-store backups with retention + a tested restore.

---

## P2 — Architecture, extensibility & product completeness

### 11. AI provider adapters incomplete (esp. local)
- Only OpenRouter + Anthropic exist. Add OpenAI/Gemini and — highest value — a
  **local Ollama/vLLM** adapter: keeps scan data in-house and sidesteps item 1's
  egress/TLS problem entirely. (roadmap T2)

### 12. Findings pipeline is coupled inline
- `evidence→asset→vuln→risk→compliance→attack` all live inside
  `_run_single_tool`. Extract named, independently testable stages (roadmap T6).

### 13. No domain event bus
- Components call each other directly; adding a subscriber means editing the
  orchestrator. Introduce an in-process event bus (`ScanCompleted`, etc.) (T11).

### 14. Storage has no provider interface
- `modules/reports/storage.py` reuses `evidence_store`'s **private**
  `_get_s3_client`/`_ensure_bucket`; no `StorageProvider` abstraction, no
  presigned URLs (roadmap T9).

### 15. Notifications are in-app only
- Single hardcoded channel, no provider interface for email/Slack/Discord/webhook
  (roadmap T8).

### 16. AWS/cloud, API-security, SSO engines not built
- Cloud scanning (T16), the API-security testing engine (authN/authZ/JWT/GraphQL/
  BOLA/injection, T17), and SSO (SAML/OIDC/Azure/Okta, T18) are unimplemented.
  Until built, feature-flag them off so nothing unsupported is advertised.

### 17. ATT&CK mapping coverage is a curated starter set
- `modules/attack/catalog.py` maps common CWEs/nuclei tags; many findings map via
  tag only (e.g. Terrapin/cwe-354 mapped through its `cve`/`network` tags, not the
  CWE). Expand coverage, ideally from a maintained CWE→ATT&CK dataset.

### 18. Real tool-execution isn't in CI
- The scan doctor (`python -m apps.api.scanner_engine.doctor`) is manual; binary or
  nuclei-template regressions won't be caught automatically. Wire it into CI as a
  gated/integration job.

### 19. Operational notes to validate
- **httpx `-tech-detect`** downloads a ~92 MB ML model on first use (`~/.dit`) —
  runtime egress + latency, and blocked entirely under TLS interception; consider
  baking it into the worker image or disabling the ML tech-detect.
- **AI attack narrative** is unproven end-to-end in the worker (blocked by item 1
  this session) — validate once egress works or via the local model.
- **Scan performance:** the full 5-tool scan took ~5.5 min (nuclei ~110s with the
  broadened tag set). Large/multi-host targets can exceed per-tool timeouts; there
  is no global scan time/concurrency budget.

---

## Suggested sequencing

1. **Unblock AI + storage resilience (P0):** custom-CA/proxy support **or** local
   model adapter (item 1 + 11), wrap evidence storage (item 2), and gate
   non-scannable target types (item 3).
2. **Ops hardening (P1):** Celery retries/queues/DLQ (5), `/metrics` lockdown (4),
   backups (10), secret store + key rotation (8).
3. **Architecture (P2):** provider adapters, pipeline extraction, event bus,
   storage/notification interfaces — in that order — then the larger product
   engines (cloud/API-security/SSO).
