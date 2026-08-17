# MBS.SC Monitoring (Phase 4.2)

Lightweight Prometheus monitoring for the production deployment. **Additive** — no app,
schema, or API changes. Alert delivery is via Alertmanager → email (R4, below); no
Grafana service or metric exporters are bundled.

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
default queue, is down, so no scheduled scans/backup/retention/reaper run),
`MbsDependencyDown` (`mbs_dependency_up{component}` == 0 for 2min — the API's short-timeout probe
of Postgres/Redis is failing; catches a Redis outage that fail-open consumers would otherwise hide).
Warning: `MbsHighScanFailureRatio`, `MbsExcessiveToolFailures`, `MbsAiCostHigh` (configurable
$ threshold in the rule), `MbsScanRecoveryActivity` (orphan-reaper/relay firing = worker-loss
or queue-backlog proxy), plus the F4/DR/AI/email alerts (DLQ, backup, retention, AI SLOs,
email-delivery).

### Alert delivery — Alertmanager → email (R4)
Fired alerts are delivered by an **`alertmanager`** service (prod overlay, published to
**`127.0.0.1:9093` only**). Prometheus routes to it (`alerting:` block in `prometheus.yml`);
config is in [`../alertmanager/alertmanager.yml`](../alertmanager/alertmanager.yml). It emails via
the **same `smtp_password` Docker Secret** as the app's E-series email — only the password is a
secret (`smtp_auth_password_file`). Before enabling: set the non-secret `smtp_smarthost` /
`smtp_from` / `smtp_auth_username` / receiver `to` in `alertmanager.yml`, and provide
`infra/secrets/smtp_password.txt`. Critical alerts repeat hourly; warnings every 4h.

## Known gaps / recommended next increments (intentionally deferred)
These need additional components and were kept out of this additive step:
- **Redis / Database "unavailable" alerts** — DONE (item A). The API exposes
  `mbs_dependency_up{component=postgres|redis}` from short-timeout synchronous probes
  (`core/observability.py::DependencyHealthCollector`, registered API-side only) and
  `MbsDependencyDown` alerts on it. No exporter required.
- **True scan-queue-depth backlog** — DONE. The API-side `ReliabilityCollector` exposes
  `mbs_queue_depth{queue="scans"|"default"}` (LLEN of each Celery broker queue's Redis list) and
  `MbsScanQueueBacklog` (scans > 50 for 15m — an operational/tunable threshold) alerts on it.
  Assumes queue name == Redis list key (no priority queues configured). No exporter required.
- **Worker counter aggregation under prefork** — DONE (W1). `worker` + `worker-default` set
  `PROMETHEUS_MULTIPROC_DIR=/run/prometheus-multiproc`, backed by a **tmpfs** (exists + writable at
  startup so there is no import-time crash, and empty on every run so no stale counter files carry
  across restarts). `metrics.py` serves a `MultiProcessCollector` that sums every prefork child's
  files, so worker task counters (`mbs_scan_*`, `mbs_tool_failure_total`, agent `mbs_ai_*`,
  `mbs_scan_reaped/relayed`, `mbs_schedule_launched`) are exported truthfully. Not set on `api`
  (multiprocess mode is incompatible with its custom collectors) or `beat` (runs no tasks).
- **Alertmanager** — DONE (R4): fired alerts are delivered to email (see "Alert delivery" above).
- **Grafana dashboards** — importable artifacts ship: `infra/grafana/ai-dashboard.json` (AI ops) and
  `infra/grafana/reliability-dashboard.json` (queue/DLQ depth, dependency health, backup/beat
  freshness, scan outcomes, reaper/relay recovery). Both reference only exported metrics (asserted by
  tests). A bundled Grafana service is still out of scope — deploy your own Grafana against the
  existing Prometheus and import the JSON.
