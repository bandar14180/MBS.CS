# MBS.CS — Production Readiness Audit

_Read-only audit. No code changed to produce this document._
_Branch: `feat/phase2-pentest-attack-mapping` · HEAD at audit time: `9160d04` · CI: 6/6 green · Suite: 741 passed / coverage 86.88%._

## Overall readiness score: **8.8 / 10 — production-ready for launch & investor demo**

| Domain | Score | One-line |
|---|---|---|
| Security | **9.0** | Strong auth/MFA, FORCE-RLS multi-tenancy, SSRF defense, secrets, log redaction, GDPR |
| Reliability | **8.5** | Excellent recovery/DR; residual infra-HA (Redis, beat SPOF, worker healthchecks) |
| AI | **9.0** | Injection hardening, allowlist backstops, fallback, budget, prompt governance, eval, observability |
| Operations | **8.5** | Full monitoring/alerts/runbooks/deploy; alert-routing + Grafana service are deployment-time |

**No P0 (critical) blockers found.** Residuals are infrastructure-HA and deployment-time concerns, not code defects.

---

## Security

**Completed / verified**
- **Authentication:** JWT HS256 (15-min access, type-scoped), refresh tokens SHA-256-hashed + rotated + revocable; **MFA** (TOTP RFC-6238, Fernet-encrypted secret at rest, hashed one-time recovery codes, two-step login, per-user Redis brute-force lockout, structured `mbs.security` audit).
- **Authorization:** RBAC (`require_permission`) + PostgreSQL **FORCE Row-Level Security** (`workspace_isolation` on ~22 tenant tables) + derived-scope enforcement + `scope_guard`.
- **SSRF:** `net_guard` blocks loopback/RFC1918/link-local/ULA/reserved/multicast and **cloud metadata**; resolves **all** A/AAAA at scan time and rejects private; IPv4-mapped forms normalized; default public-only.
- **Secrets:** `<NAME>_FILE` convention (Docker Secrets/Vault), never logged; `validate_production()` blocks placeholder secrets, wildcard CORS/hosts, disabled TLS, public metrics.
- **API exposure:** rate limiting, TrustedHost, security headers/HSTS, explicit prod CORS, token-gated `/metrics`.
- **Logging privacy:** centralized redaction scrubs passwords/tokens/emails/API keys; error contract returns generic bodies (no stack/secret leakage).
- **GDPR:** data export (incl. scans/reports/audit, metadata-only), erasure/anonymization, retention.

**Residual risks** — none critical. External pen-test / WAF are deployment-time validations, not code gaps.

## Reliability

**Completed / verified**
- **Workers:** split topology (scans / default / beat), `acks_late` + `reject_on_worker_lost` + `prefetch=1`, per-task soft/hard time limits, `max_tasks_per_child`.
- **Retries:** transient-only classification; **DLQ** (Redis) + replay tooling.
- **Graceful shutdown:** soft-timeout self-terminates a scan cleanly (reclaimable); warm SIGTERM; deployment runbook.
- **Recovery:** orphan reaper, queued relay, atomic scan claim.
- **DR:** DR-1..4 — durable backup volume, AES-256-GCM encryption, off-site replication, freshness gauge + manual restore drill.
- **Retention:** enabled in prod at **Stage 1 (plan-only / dry-run)**.

**Residual risks**
- **R1 (Med):** **Redis is a single point** (broker + DLQ + cache + rate-limit + budget). No HA/persistence configured — loss drops the queue/DLQ and in-flight acks; budget/rate-limit fail-open. *(infra/architecture decision)*
- **R2 (Med):** **Beat scheduler SPOF** with no liveness alert — if beat dies, reaper/backup/retention/relay ticks stop (`restart: unless-stopped` mitigates the outage; the gap is the missing signal).
- **R3 (Low-Med):** No compose **healthchecks** on workers/beat (only restart policy).

## AI

**Completed / verified**
- **Safety boundaries (AI-1):** untrusted-input sanitization + `<<UNTRUSTED>>` delimiting; output validation blocks exploit/destructive/"disable-a-control" content → safe fallback; secret/PII redaction on AI outputs; `mbs.ai.security` decision audit. **Non-bypassable backstops:** tool allowlist, no-target decision schema, scope enforcement.
- **Hallucination prevention:** correlator/FP id-filtering (never invents/drops findings), agent allowlist, remediation groundedness; assistant forbidden from inventing finding details — all scored by the eval gate.
- **Fallback (AI-2.1):** deterministic provider chain, availability-only failover, degradation preserved.
- **Budget (AI-2.2):** per-workspace daily cap + circuit-breaker (fail-open); cost reporting endpoint; config-driven pricing.
- **Prompt governance (AI-2.3):** registry + content-hash **drift guard** + changelog (CI-enforced).
- **Evaluation (AI-2.4):** offline quality gate — agent tool-selection, correlator, remediation groundedness, **MITRE ATT&CK accuracy** (golden precision/recall), injection regression.
- **Observability (AI-2.5):** latency histogram + error-rate counter + SLO alerts (`MbsAiLatencySlo`, `MbsAiErrorRateHigh`, `MbsAiFailoverActive`) + Grafana dashboard artifact.

**Residual risks** — none critical. Latency persistence (historical trend) and live model-comparison are deferred by design.

## Operations

**Completed / verified**
- **Monitoring:** Prometheus scrapes api + both workers; F4 reliability collector; broad alert set (API/worker down, 5xx, scan/tool failure, AI cost/budget/latency/error/failover, DLQ, backup fail/stale, retention, email).
- **Docs/runbooks:** backup-restore, disaster-recovery, deployment, retention, email-alerts; AI prompts-changelog / evaluation / observability; data-privacy-policy; **+ this audit**.
- **Deployment:** prod compose overlay (file secrets, rate-limit, HSTS, token metrics, Prometheus, backups+encryption, retention Stage-1, email template). **6 CI gates** (tests+coverage≥80, supply-chain pip-audit `--strict`, gitleaks, Trivy api/worker, scan-doctor).

**Residual risks**
- **R4 (Low):** No Alertmanager **routing** wired (rules exist; notification routing is a deployment concern).
- **R5 (Low):** Retention **Stage-2 go-live** is a pending operator step (dry-run → backup → flip `RETENTION_DRY_RUN=false`).
- **R6 (Info):** Grafana **dashboard is import-only** (no bundled service — deliberate).

---

## Remaining risks (consolidated, ranked)
| # | Risk | Severity | Nature |
|---|---|---|---|
| R1 | Redis single-point (no HA/persistence) | Med | Infra/architecture |
| R2 | Beat scheduler SPOF, no liveness alert | Med | Reliability observability |
| R3 | No worker/beat compose healthchecks | Low-Med | Infra |
| R4 | No Alertmanager routing | Low | Deployment |
| R5 | Retention still Stage-1 (dry-run) | Low | Operator action |
| R6 | AI latency not persisted; no model-comparison | Low | Deferred by design |

## Recommended next improvements
- **P0 (blockers):** **none.** The platform is production-ready.
- **P1 (operational / investor-facing):**
  1. **Beat-liveness signal + `MbsBeatStalled` alert** — a beat heartbeat timestamp (mirrors the DR-4 backup-freshness pattern) → closes R2. Additive, in-pattern, testable.
  2. **Redis durability/HA** — AOF persistence (or managed/HA Redis) for the broker/DLQ → mitigates R1. *(infra/architecture decision — requires approval.)*
  3. **Worker/beat compose healthchecks** → R3.
- **P2 (deployment-time):** Alertmanager routing (R4); Retention Stage-2 go-live after a validated dry-run + backup (R5); optional bundled Grafana service.

## Conclusion
MBS.CS is a **mature, production-hardened, investor-demo-ready** platform with strong security, reliability, and a comprehensively-governed AI pipeline. There are **no critical (P0) blockers**. The highest-value next step is the **beat-liveness alert (P1.1)** — additive and low-risk — followed by the infra-HA items (R1/R3), which are architecture/deployment decisions and should be scoped with explicit approval.
