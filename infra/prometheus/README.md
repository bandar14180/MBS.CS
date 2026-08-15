# MBS.SC Monitoring (Phase 4.2)

Lightweight Prometheus monitoring for the production deployment. **Additive** — no app,
schema, or API changes; no Grafana/Alertmanager/exporters added.

## What runs
Enabled by the **production** overlay:
```
docker compose -f infra/docker-compose.yml -f infra/docker-compose.prod.yml up -d prometheus
```
- `prometheus` (pinned image) scrapes over the internal compose network and is published to
  **`127.0.0.1:9090` only** (never public).

## What it scrapes (`prometheus.yml`)
| Job | Target | Auth |
| --- | --- | --- |
| `mbs-api` | `api:8000/metrics` | `x-metrics-token` header read from the mounted `metrics_token` secret (`METRICS_MODE=token` unchanged) |
| `mbs-worker` | `worker:9100/` | none (internal-only endpoint from Phase 4.1) |

**No secret is stored in `prometheus.yml`** — the token comes from `/run/secrets/metrics_token`
(the same secret the API uses). Ensure `infra/secrets/metrics_token.txt` has **no trailing
newline** so the header matches the API's stripped token.

## Alerts (`alerts.yml`)
Critical: `MbsApiDown`, `MbsWorkerDown`, `MbsApiHighServerErrorRate` (5xx > 5%),
`MbsBeatStalled` (no beat heartbeat > 3min — the scheduler, or worker-default draining the
default queue, is down, so no scheduled scans/backup/retention/reaper run).
Warning: `MbsHighScanFailureRatio`, `MbsExcessiveToolFailures`, `MbsAiCostHigh` (configurable
$ threshold in the rule), `MbsScanRecoveryActivity` (orphan-reaper/relay firing = worker-loss
or queue-backlog proxy). Prometheus evaluates the rules; wiring them to a notifier
(Alertmanager) is a deliberate follow-up.

## Known gaps / recommended next increments (intentionally deferred)
These need additional components and were kept out of this additive step:
- **Redis / Database "unavailable" alerts** — require `redis_exporter` / `postgres_exporter`
  (or a small `mbs_dependency_up{component}` gauge fed by the app's `/ready` probe). Add as a
  scoped follow-up.
- **True scan-queue-depth backlog** — needs a Celery/Redis queue-depth exporter. Until then
  `MbsScanRecoveryActivity` is the backlog proxy.
- **Worker counter aggregation under prefork** — the worker `:9100` endpoint reports
  target *liveness* (`up{}`) and metric families now; full per-child counter values require
  `PROMETHEUS_MULTIPROC_DIR` set on the worker with a pre-created, writable dir at the
  container entrypoint (avoids a startup crash). A separate, tested change.
- **Alertmanager / Grafana dashboards** — out of scope for this phase.
