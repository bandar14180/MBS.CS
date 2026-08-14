# Runbook: Email Alert System (E1–E5)

Async, provider-abstracted email alerts for high-signal events. **Default OFF** and **additive**:
with `EMAIL_ENABLED=false` nothing is ever sent. Delivery is always asynchronous (a Celery task
on the `default` queue) — the scan and backup paths only *enqueue*, so a slow or broken SMTP
server can never delay or fail a scan.

## What triggers an email
| Category | Source | Recipients |
|---|---|---|
| `scan_failed` | a scan reaches `failed` (`notify_scan_finished`) | workspace members |
| `critical_findings` | a completed scan surfaced new high/critical findings | workspace members |
| `backup_failed` | a scheduled backup run failed (`dr.service.run_backup`) | `EMAIL_ADMIN_RECIPIENTS` |
| `reliability_dlq` | a scan was permanently dead-lettered (`_record_dlq`) | `EMAIL_ADMIN_RECIPIENTS` |

Info-level scan completions are **in-app only** (never emailed), to avoid noise.

## Flow
```
event / failure  ->  alerts.email_scan_alert | email_system_alert   (gated, best-effort, never raises)
                 ->  notifications.send_email  (Celery, default queue: retry + backoff + dedup)
                 ->  EmailNotificationProvider -> smtplib (STARTTLS)
```

## Configuration (environment)
| Var | Default | Purpose |
|---|---|---|
| `EMAIL_ENABLED` | `false` | master switch |
| `EMAIL_PROVIDER` | `smtp` | transport (only `smtp` today) |
| `SMTP_HOST` | — | SMTP server host (**required when enabled**) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | — | SMTP auth user (blank = no auth) |
| `SMTP_PASSWORD` / `SMTP_PASSWORD_FILE` | — | SMTP password via env or Docker Secret / Vault |
| `SMTP_USE_TLS` | `true` | STARTTLS after connect |
| `SMTP_TIMEOUT_SECONDS` | `15` | socket timeout |
| `EMAIL_FROM_ADDRESS` | — | From header (**required when enabled**) |
| `EMAIL_ADMIN_RECIPIENTS` | `[]` | recipients for system alerts (backup/DLQ), JSON list |
| `EMAIL_DEDUP_WINDOW_SECONDS` | `300` | identical alerts collapsed within this window |
| `EMAIL_MAX_RETRIES` | `3` | Celery retries for transient SMTP faults |
| `EMAIL_TASK_SOFT/TIME_LIMIT_SECONDS` | `25` / `40` | per-task time budget |

Production startup (`validate_production`) refuses to boot if `EMAIL_ENABLED=true` without
`SMTP_HOST` + `EMAIL_FROM_ADDRESS` (fail closed).

## Enabling email
1. Set the SMTP vars above (password via `SMTP_PASSWORD_FILE` → a Docker Secret / Vault file).
2. Set `EMAIL_ADMIN_RECIPIENTS` for system alerts.
3. Set `EMAIL_ENABLED=true` on **worker-default** (runs the task) and **beat/worker** (so the
   DLQ path can enqueue). See the commented block in `infra/docker-compose.prod.yml`.
4. Redeploy. Verify with the metrics below.

## Production safety
- **Async only** — never sent inside a scan/backup; callers enqueue and move on.
- **Retry + backoff** — transient SMTP faults retry with exponential backoff (5s→…, capped 5m),
  up to `EMAIL_MAX_RETRIES`; permanent failures are recorded and dropped (no retry storm).
- **Dedup** — Redis `SET NX EX` collapses identical `(category, workspace, subject)` alerts
  within `EMAIL_DEDUP_WINDOW_SECONDS`, preventing email storms from a flapping failure.
- **No leakage** — messages are generic (no evidence, tokens, internal URLs); outgoing subject/
  body are run through the central log-redaction pass as defense-in-depth. Audit events carry a
  recipient **count** and category only — never an address or the body.
- **Best-effort dispatch** — a dispatch/enqueue error never affects the scan, backup, or in-app
  notification.

## Observability
- Metrics (worker scrape target): `mbs_email_sent_total`, `mbs_email_failed_total`,
  `mbs_email_duration_seconds` (label `category`).
- Audit (`mbs.security` logger): `notification.email.sent`, `notification.email.failed`.
- Alert: `MbsEmailDeliveryFailing` fires when `increase(mbs_email_failed_total[1h]) > 0`.

## Troubleshooting
| Symptom | Likely cause | Action |
|---|---|---|
| No emails, no metrics | `EMAIL_ENABLED=false` or task not enqueued | confirm flag on worker-default; check `mbs.notifications` logs |
| `notification.email.failed` events | SMTP auth/host/TLS wrong | verify `SMTP_*`; check the server accepts STARTTLS on the port |
| Startup refuses to boot | `EMAIL_ENABLED=true` but host/from missing | set `SMTP_HOST` + `EMAIL_FROM_ADDRESS` |
| One alert, expected many | dedup window collapsing identical alerts | expected; widen/narrow `EMAIL_DEDUP_WINDOW_SECONDS` |
| Emails delayed | transient SMTP faults retrying with backoff | check `mbs_email_failed_total`; inspect SMTP server health |

## Scope / limitations (this phase)
- **No user notification preferences yet** — recipients are all active workspace members
  (scan alerts) or `EMAIL_ADMIN_RECIPIENTS` (system alerts). Per-user opt-in/out is a later phase
  (requires a migration).
- SMTP is the only transport today; the provider abstraction leaves room for HTTP providers.
