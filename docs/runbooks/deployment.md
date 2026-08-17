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
- Disaster recovery / backups: `disaster-recovery.md`, `backup-restore.md`
- DLQ replay: `dlq-replay.md` (planned) — inspect/replay dead-lettered scans
- Retention enablement: `retention.md`
- Email alerts: `email-alerts.md`
