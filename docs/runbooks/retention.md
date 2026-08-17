# Runbook: Data Retention Enablement

Retention prunes aged data per resource so storage and tables don't grow unbounded. It is
**double-gated** and ships OFF; it is turned on in **two stages** so live deletion never happens
by surprise. Deletion (including object-store deletes of evidence + report PDFs) is
**irreversible** except by restoring a DR backup — treat the switch to live with care.

## Gates (both must be satisfied to delete)
| Setting | Effect |
|---|---|
| `RETENTION_ENABLED` | `false` → the purge is a no-op and the beat entry isn't even registered |
| `RETENTION_DRY_RUN` | `true` → the task only **plans** (counts what it *would* delete); deletes nothing |

Live deletion happens **only** when `RETENTION_ENABLED=true` **AND** `RETENTION_DRY_RUN=false`.

## Retention windows (defaults, in days)
| Resource | Window | Setting |
|---|---|---|
| Raw scan evidence (objects + rows) | 90 | `RETENTION_EVIDENCE_DAYS` |
| Scan records + non-finding subtree | 180 | `RETENTION_SCAN_DAYS` |
| AI usage/cost log | 180 | `RETENTION_AI_USAGE_DAYS` |
| Generated reports (rows + PDFs) | 365 | `RETENTION_REPORT_DAYS` |
| In-app notifications | 90 | `RETENTION_NOTIFICATION_DAYS` |
| Expired refresh tokens (grace) | 7 | `RETENTION_REFRESH_TOKEN_GRACE_DAYS` |
| Audit events (compliance window) | 730 | `RETENTION_AUDIT_DAYS` |

Blast radius per run is bounded by `RETENTION_BATCH_SIZE` (default 500 / resource) and
`RETENTION_MIN_KEEP` (default 10 newest / resource are never deleted). Per-workspace commits mean
partial progress is kept and the next run resumes. Runs on the `default` queue (never `scans`).

## CLI (manual, for validation)
```bash
python -m apps.api.retention plan       # print windows + cutoffs (pure; no DB)
python -m apps.api.retention dry-run     # count eligible rows/objects per resource; deletes nothing
python -m apps.api.retention run         # LIVE purge -- still honors the two gates
```

## Scheduled task
Beat emits `retention.purge` every `RETENTION_INTERVAL_SECONDS` (default daily) **only when
`RETENTION_ENABLED=true`**; `worker-default` executes it. The task returns
`{mode: disabled|dry_run|live|timeout, total_eligible, resources:[...]}` and logs
`retention.task.completed mode=… total_eligible=…`.

## Current state — Stage 1 (plan-only) — ACTIVE
`infra/docker-compose.prod.yml` sets, on **worker-default** and **beat**:
```
RETENTION_ENABLED=true
RETENTION_DRY_RUN=true
```
So production **schedules** a daily retention pass that **plans only** — it meters
`total_eligible` / `would_delete` and touches no data.

## Stage 2 — go live (do NOT perform until validated)
1. **Validate Stage 1:** let ≥1–2 daily cycles run. Confirm `retention.task.completed mode=dry_run`
   and review `total_eligible` / per-resource `would_delete` in logs. Sanity-check the counts
   against expectations (no surprises, e.g. evidence/notifications dominating).
2. **Confirm monitoring:** `mbs_retention_failures_total` is flat; `MbsRetentionFailing` not firing.
3. **Take a fresh DR backup** (`python -m apps.api.dr backup`, verified) — this is the only way to
   recover mistakenly-purged data.
4. **Flip the gate:** set `RETENTION_DRY_RUN=false` on **worker-default** and **beat**; redeploy both.
5. **Monitor:** the first live pass may clear a backlog; it is bounded to `RETENTION_BATCH_SIZE`
   per resource per run, so it converges over several daily cycles rather than one huge delete.
   Watch DB size, object-store size, and `mbs_retention_failures_total`.

## Rollback (instant, no code)
- Set `RETENTION_DRY_RUN=true` (back to plan-only) **or** `RETENTION_ENABLED=false` (no-op) on
  worker-default + beat and redeploy. Both gates are honored on every run.
- **Already-deleted data is not recoverable** except by restoring the pre-Stage-2 DR backup —
  which is why the backup in Stage 2 step 3 is mandatory. `RETENTION_MIN_KEEP` guarantees the
  newest N per resource are never deleted.

## Notes
- Audit events are kept 730 days for compliance even after the actor is GDPR-erased (the actor
  email is anonymized; see docs/security/data-privacy-policy.md).
- No database migration is involved in enabling retention.
