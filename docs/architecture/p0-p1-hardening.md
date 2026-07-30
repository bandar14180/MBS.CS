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
mirrors env. `tests/test_scans.py`: unsupported target type → 400. Full suite:
**131 passed**.
