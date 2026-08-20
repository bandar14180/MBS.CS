# Runbook: Deployment, Rolling Restart & Graceful Shutdown

How to deploy MBS.CS without losing in-flight scans or corrupting state. The system is built to
tolerate abrupt worker loss (acks_late redelivery + orphan reaper), but a *clean* rollout avoids
unnecessary scan restarts and downtime.

## Components
| Service | Role | Shutdown behavior |
|---|---|---|
| `api` | FastAPI/uvicorn HTTP | drains in-flight requests on SIGTERM |
| `worker` | Celery `-Q scans` (heavy scans) | warm shutdown: finishes in-flight scan, `stop_grace_period=60s` |
| `worker-default` | Celery `-Q default` (reaper, relay, schedule, backup, retention, email) | warm shutdown, `stop_grace_period=60s` |
| `beat` | scheduler (emits periodic ticks) | stateless emitter, `stop_grace_period=30s`; missed tick re-emits next interval |
| `postgres` / `redis` / `minio` | stateful | see DR runbook; not restarted casually |

## Reliability guarantees you can rely on during a deploy
- **acks_late + reject_on_worker_lost + prefetch=1:** a scan is acknowledged only after it
  finishes; a worker killed mid-scan → the broker redelivers it. Scans are idempotent (the
  orchestrator skips an already-terminal scan), so redelivery is safe.
- **Per-task soft/hard time limits:** a hung scan self-terminates (marked `failed`, reclaimable)
  before the hard SIGKILL, so it never blocks warm shutdown forever.
- **Orphan reaper:** any scan stuck `running` past `SCAN_ORPHAN_TIMEOUT_SECONDS` (2h) is recovered
  by `scans.reap_orphans` (beat, every 5m). It marks state; it never re-dispatches (no dup runs).

## Migration ordering (schema changes)
Always apply migrations **before** rolling the app/worker image that expects the new schema:
```bash
# 1) apply migrations (idempotent; safe to run repeatedly)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.prod.yml run --rm api \
  sh -lc 'cd /srv/db && alembic upgrade head'
# 2) then roll the services (below)
```
Migrations in this repo are additive; a brief window where old code runs against the new schema is
tolerated. Never roll app code that requires a migration that hasn't been applied yet.

## TLS trust at build time
Production builds require **no** local CA file: the images verify PyPI / GitHub / npm
against the public root store shipped in their base image, and no interception root is
baked into any layer. The optional `extra_ca` BuildKit secret is a **developer-machine
convenience** for networks that intercept TLS (see the README); it is supplied by a
gitignored `infra/docker-compose.local-ca.yml` overlay that is never applied here. If a
build on a production host fails TLS verification, treat it as a network/proxy problem
to fix at the network layer — do not disable verification and do not add the overlay.

## Rolling restart (no scan loss)
Order matters: drain scan workers first, then the rest.
```bash
COMPOSE="-f infra/docker-compose.yml -f infra/docker-compose.prod.yml"

# 1) Scan workers: SIGTERM triggers warm shutdown -> current scan finishes (up to 60s),
#    then the container stops. New image starts and picks up the queue.
docker compose $COMPOSE up -d --no-deps --build worker

# 2) Default worker (reaper/relay/schedule/backup/retention/email).
docker compose $COMPOSE up -d --no-deps --build worker-default

# 3) Beat (stateless; a missed tick re-emits next interval).
docker compose $COMPOSE up -d --no-deps --build beat

# 4) API (uvicorn drains in-flight requests on SIGTERM).
docker compose $COMPOSE up -d --no-deps --build api

# 5) Web/nginx if changed.
docker compose $COMPOSE up -d --no-deps --build web nginx
```
Notes:
- A scan longer than `stop_grace_period` (60s) at shutdown is SIGKILLed and **redelivered**
  (acks_late) or recovered by the reaper — no data loss, just a restart of that scan.
- Only **one** `beat` must run (it's the scheduler). Do not scale it to >1.
- To scale scan throughput, scale `worker` replicas; keep `worker-default` and `beat` singular.

## Graceful shutdown / drain (single service)
```bash
# Stop accepting new work and let in-flight finish (warm shutdown), then stop:
docker compose $COMPOSE stop -t 60 worker           # -t >= stop_grace_period
```
`beat` can be stopped anytime (`-t 30`); the schedule resumes when it restarts.

## Health / readiness
- API liveness: `GET /health` (process up). Readiness: `GET /ready` (probes Postgres + Redis; 503
  if either is down) — gate load-balancer traffic on `/ready`.
- Workers expose Prometheus metrics on `:9100` (scraped by Prometheus). There is no per-container
  compose healthcheck on workers yet (tracked as a reliability follow-up); `restart: unless-stopped`
  covers process crashes.

## Production configuration: `TRUSTED_PROXY_COUNT`

**The API refuses to start in production unless this is set explicitly.** There is no safe
default to inherit, so the guard forces a decision rather than assuming your topology.

**The shipped overlay declares `TRUSTED_PROXY_COUNT: "1"`** — correct for the bundled topology
and nothing else. Set it in `infra/docker-compose.prod.yml`, **not in `.env`**: that service's
`environment:` mapping overrides the base file's `env_file: ../.env`, so a value placed in
`.env` is silently ignored for the API. `apps/api/tests/test_deployment_config.py` asserts the
overlay keeps satisfying `validate_production()`, so a future guard cannot regress unnoticed.

**What it is.** The number of proxies in front of this app that **append** to `X-Forwarded-For`.
The client's own address is then read as the **Nth entry from the right** — everything further
left is caller-supplied and forgeable. It is used for one thing: the rate-limit bucket key for
*anonymous* requests (authenticated requests bucket by user id and are unaffected).

- `0` — nothing appends in front. `X-Forwarded-For` is ignored entirely and the direct socket
  peer is used. **This is a valid and safe answer**; it just has to be chosen deliberately.
- `1` — one appending proxy (e.g. only the bundled `nginx`).
- `2` — two, e.g. an external load balancer or CDN in front of `nginx`.

**How to determine it — never guess.** From a client whose public IP you know, send a request to
production and read the raw `X-Forwarded-For` the API receives. Count the entries: if the header
holds exactly one entry equal to your real client IP, the answer is `1`; if two, `2`. Count only
proxies that *append* — a CDN that sets its own header (e.g. `CF-Connecting-IP`) but also appends
to `X-Forwarded-For` still counts as a hop.

**Why guessing is unsafe in both directions.**
- Too **low**: every anonymous client collapses into the proxy's single bucket, so the limiter
  throttles all unauthenticated traffic together — or effectively not at all.
- Too **high**: the Nth-from-right read reaches into caller-controlled entries, so any client can
  mint a fresh bucket per request by varying the header. This is worse than having no limiter.

**Prerequisite before using any non-zero value.** The API must be unreachable except *through*
the proxy chain. If a client can reach `:8000` directly, it supplies the whole
`X-Forwarded-For` header and any `N > 0` becomes attacker-controlled.

The shipped files already satisfy this, and the arrangement is deliberate: a compose `ports`
list is **appended** across `-f` files, never replaced, so a publication in the base file could
not be withdrawn by an overlay. Therefore:

| File | API host port | Applies to |
|---|---|---|
| `docker-compose.yml` (base) | none | always — in-network `api:8000` only |
| `docker-compose.override.yml` | `8000:8000` | dev only; auto-merged by a bare `docker compose up`, excluded from any explicit `-f` list |
| `docker-compose.prod.yml` | `127.0.0.1:8000:8000` | production — host-local ops (`curl http://127.0.0.1:8000/ready`) |

In production the only externally reachable entrypoint is `nginx` on `:80`. **If you publish
the API port yourself, put it back behind a firewall or return `TRUSTED_PROXY_COUNT` to `0`** —
`apps/api/tests/test_deployment_config.py` fails the build if any file in the production merge
publishes the API on a routable interface while the hop count is non-zero.

Note the bundled `nginx.conf` listens on `:80` with no TLS directives. If you serve HTTPS,
something upstream terminates TLS — and that hop counts.

## Post-deploy verification
- `GET /ready` → `ready`.
- Prometheus targets `mbs-api`, `mbs-worker` (worker:9100 + worker-default:9100) all `up`.
- No new `MbsWorkerDown` / `MbsApiDown` / `MbsDlqBacklog` alerts.
- A test scan completes end-to-end; `mbs_scan_success_total` increments.

## Rollback
- Re-deploy the previous image tag with the same rolling order above.
- If a migration must be undone, use the matching `alembic downgrade` **before** rolling back code
  — but prefer forward fixes; downgrades are a last resort.

## Related runbooks
- Disaster recovery / backups: `disaster-recovery.md`
- DLQ replay: `dlq-replay.md` (planned) — inspect/replay dead-lettered scans
- Retention enablement: `retention.md`
- Email alerts: `email-alerts.md`
