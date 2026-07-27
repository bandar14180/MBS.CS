# MBS.SC — Architecture & Implementation Blueprint
**Smart Security. Fast Results.**

This document is the single source of truth for building MBS.SC in Claude Code. It covers architecture, data model, APIs, AI workflow, tool orchestration, security model, and a phased build order. Every non-trivial decision includes the reasoning and trade-off so future changes don't accidentally break an assumption baked in elsewhere.

---

## 1. Product Framing (read this first)

MBS.SC is **not** an autonomous "AI hacks things" product. It is an **orchestration and reasoning layer over deterministic, well-understood security tools**, with these hard rules baked into the architecture itself (not just policy):

- Every scan requires a **verified, authorized target** (ownership/authorization proof gate before any active testing module can fire).
- AI **never executes exploits or generates payloads freely** — it selects from a curated, versioned tool catalog and pre-approved playbooks, and only *validates/interprets* structured tool output.
- Every finding is **traceable to raw tool evidence**. If there's no evidence artifact, it cannot become a "finding."
- All destructive/active modules (SQLMap active mode, Metasploit validation, brute-force modules) are **opt-in per scan**, require an explicit authorization scope, and are rate/impact limited.

This framing drives several architecture decisions below (evidence store, authorization service, tool sandboxing), so keep it in mind when extending the system.

---

## 2. High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                            CLIENT LAYER                                 │
│   Next.js Dashboard (SSR) · Mobile-responsive Web · Public API Docs     │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │ HTTPS (TLS1.3) via Nginx
┌───────────────────────────────▼──────────────────────────────────────────┐
│                          API GATEWAY LAYER                              │
│   Nginx reverse proxy → FastAPI Gateway (authN/z, rate limit, routing)  │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │
        ┌────────────────────────┼──────────────────────────────┐
        ▼                        ▼                              ▼
┌───────────────┐      ┌──────────────────┐          ┌────────────────────┐
│  CORE SERVICES │      │  SCAN SUBSYSTEM  │          │   AI SUBSYSTEM     │
│ Auth, Users,   │      │ Orchestrator,    │          │ Planner, Correlator│
│ Workspaces,    │      │ Tool Runners,    │◄────────►│ Validator, Risk    │
│ Projects,      │      │ Evidence Store   │          │ Engine, Reporter   │
│ Assets, RBAC   │      │ (Celery workers) │          │ (LLM via API)      │
└───────┬────────┘      └────────┬─────────┘          └──────────┬─────────┘
        │                        │                               │
        └────────────┬───────────┴───────────────┬───────────────┘
                      ▼                           ▼
              ┌───────────────┐          ┌──────────────────┐
              │  PostgreSQL   │          │  Redis + Celery   │
              │  (system of   │          │  (queues, cache,  │
              │   record)     │          │   locks, pub/sub) │
              └───────────────┘          └──────────────────┘
                      │
                      ▼
              ┌───────────────┐
              │  MinIO / S3   │  (raw tool output, screenshots, PDFs)
              └───────────────┘
```

**Why this shape:** a gateway-fronted set of services rather than a monolith, but *not* full microservices from day one. Reasoning: a pentest platform's load is bursty and job-shaped (scans), not request-shaped — the thing that actually needs independent scaling is the **scan execution layer** (CPU/network heavy, spiky) versus the **web/API layer** (steady, cheap). Splitting everything into 15 microservices on day one adds massive operational overhead (15 deploy pipelines, 15 sets of retries/timeouts) for a team that hasn't validated the domain model yet. Splitting into **3 deployable units** — API/core, Scan Workers, AI Workers — gets 90% of the scaling benefit with a fraction of the complexity, and each unit can be split further later (see §13 Future Expansion).

---

## 3. Module Breakdown

| Module | Responsibility | Why it's a separate module |
|---|---|---|
| **Auth Service** | JWT issuance/refresh, SSO/OIDC (enterprise), MFA, session mgmt | Security-critical, needs its own audit trail and rotation policy independent of business logic |
| **User & RBAC Service** | Users, roles, permissions, workspace membership | Permission checks must be centrally testable — one bug here is a breach |
| **Workspace/Org Service** | Multi-tenant boundary, billing tier, org settings | Tenant isolation is a first-class concern, not an afterthought |
| **Project Service** | Groups targets/scans under an engagement | Maps to how real pentest engagements are scoped and reported |
| **Asset Management** | Inventory of domains, IPs, repos, cloud accounts | Assets outlive individual scans — needed for trend/history views |
| **Authorization/Scope Service** | Stores proof-of-ownership, signed scope docs, active-testing consent | **This is the guardrail module.** Scanner Engine calls this before anything active runs |
| **Scanner Engine / Orchestrator** | Job DAG builder, tool scheduling, retries, timeouts | Decouples "what tools to run" from "how tools run" |
| **Tool Runner (per-tool adapters)** | Normalizes each tool's CLI/output into a common schema | New tool = new adapter, not a core code change (extensibility requirement) |
| **Evidence Store** | Raw output, screenshots, request/response pairs | Every finding must cite an evidence ID — enables audit and dispute resolution |
| **AI Agent Service** | Planning, correlation, exploit-validation reasoning, FP reduction, remediation writing, report drafting | Isolated so LLM provider/version can change without touching scan logic |
| **Vulnerability Engine** | Dedupe, normalize, CVSS calc, lifecycle (open/fixed/accepted) | Vulnerabilities persist across re-scans; needs its own state machine |
| **Risk Engine** | Business-impact scoring, asset criticality weighting | Distinct from CVSS (technical) — this is contextual/business severity |
| **Reporting Engine** | Templating, PDF generation, exec vs technical views | Heavy formatting logic shouldn't live inside the AI service |
| **Compliance Engine** | Maps findings → OWASP/NIST/ISO/PCI/CIS control IDs | A mapping table + rules engine, not a scanner |
| **Notification Service** | Email/Slack/Webhook on scan events, new criticals | Fan-out consumer of the event bus, replaceable independently |
| **Dashboard/Analytics Service** | Aggregations, trends, security score computation | Read-optimized, can use materialized views/caching without touching write path |
| **Audit Logging** | Immutable log of every privileged action | Compliance requirement (SOC2/ISO) — append-only store, separate from app DB ideally |

---

## 4. Folder Structure

```
mbs-sc/
├── apps/
│   ├── web/                        # Next.js + TypeScript + Tailwind
│   │   ├── app/
│   │   │   ├── (auth)/
│   │   │   ├── (dashboard)/
│   │   │   │   ├── projects/
│   │   │   │   ├── scans/
│   │   │   │   ├── vulnerabilities/
│   │   │   │   ├── reports/
│   │   │   │   ├── assets/
│   │   │   │   ├── compliance/
│   │   │   │   └── settings/
│   │   │   └── layout.tsx
│   │   ├── components/
│   │   │   ├── ui/                 # design-system primitives
│   │   │   ├── charts/
│   │   │   └── scan/
│   │   ├── lib/
│   │   │   ├── api-client.ts
│   │   │   └── auth.ts
│   │   └── styles/
│   │
│   └── api/                        # FastAPI monorepo service, modular by domain
│       ├── main.py
│       ├── core/
│       │   ├── config.py
│       │   ├── security.py         # JWT, password hashing
│       │   ├── deps.py             # shared FastAPI dependencies
│       │   └── rate_limit.py
│       ├── modules/
│       │   ├── auth/
│       │   │   ├── router.py
│       │   │   ├── service.py
│       │   │   ├── schemas.py
│       │   │   └── models.py
│       │   ├── users/
│       │   ├── workspaces/
│       │   ├── projects/
│       │   ├── assets/
│       │   ├── authorization_scope/  # ownership/consent gate
│       │   ├── scans/
│       │   ├── vulnerabilities/
│       │   ├── risk/
│       │   ├── reports/
│       │   ├── compliance/
│       │   ├── notifications/
│       │   ├── dashboard/
│       │   └── audit/
│       ├── ai_agent/
│       │   ├── planner.py           # decides tool sequence for a target type
│       │   ├── correlator.py        # merges multi-tool findings
│       │   ├── validator.py         # exploitability reasoning over evidence
│       │   ├── fp_reducer.py
│       │   ├── risk_scorer.py
│       │   ├── remediation_writer.py
│       │   ├── report_writer.py
│       │   └── prompts/             # versioned prompt templates
│       ├── scanner_engine/
│       │   ├── orchestrator.py      # builds/executes job DAG
│       │   ├── tool_runners/
│       │   │   ├── base.py          # common adapter interface
│       │   │   ├── nmap_runner.py
│       │   │   ├── zap_runner.py
│       │   │   ├── nuclei_runner.py
│       │   │   ├── sqlmap_runner.py
│       │   │   ├── amass_runner.py
│       │   │   ├── subfinder_runner.py
│       │   │   ├── httpx_runner.py
│       │   │   ├── naabu_runner.py
│       │   │   ├── gobuster_runner.py
│       │   │   ├── ffuf_runner.py
│       │   │   ├── nikto_runner.py
│       │   │   ├── whatweb_runner.py
│       │   │   └── metasploit_runner.py   # validation-only, gated
│       │   ├── evidence_store.py
│       │   └── sandbox/             # per-tool container isolation config
│       ├── celery_app/
│       │   ├── worker.py
│       │   └── tasks/
│       └── tests/
│
├── infra/
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.worker
│   │   ├── Dockerfile.web
│   │   └── tool-images/            # one hardened image per security tool
│   ├── nginx/
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   └── k8s/                        # added at scale-out phase, see §13
│
├── db/
│   ├── migrations/                 # Alembic
│   └── seeds/
│
└── docs/
    ├── api-spec.yaml               # OpenAPI
    └── architecture/                # this file lives here
```

**Why this structure:** modular monolith on the backend (`modules/` by domain, not by technical layer) so each module can be lifted into its own service later without a rewrite — you just move a folder and give it its own `main.py`. The `tool_runners/` adapter pattern is the key extensibility point requested: adding a new tool means writing one adapter class implementing `base.py`'s interface (`run()`, `parse()`, `to_common_schema()`), not touching the orchestrator.

---

## 5. Database Design

Design principles: every finding must trace to evidence and a tool run; every privileged action must be auditable; multi-tenancy enforced via `workspace_id` on every tenant-owned table (not just at the app layer — add row-level security policies in Postgres as defense in depth).

### Core tables

**users**
`id (uuid, pk), email (unique), password_hash, full_name, mfa_enabled, mfa_secret_encrypted, status (active/suspended), created_at, last_login_at`

**workspaces**
`id (uuid, pk), name, plan_tier, owner_user_id (fk users), created_at`

**workspace_members**
`id, workspace_id (fk), user_id (fk), role_id (fk), invited_at, joined_at`

**roles**
`id, workspace_id (fk, nullable for system roles), name, description`

**permissions**
`id, key (e.g. "scan:create", "report:export"), description`

**role_permissions**
`role_id (fk), permission_id (fk)` — composite pk

**projects**
`id, workspace_id (fk), name, description, status, created_by (fk users), created_at`

**targets**
`id, project_id (fk), type (domain/ip_range/api/cloud_account/repo), value, added_by, created_at`

**authorization_scopes** *(the guardrail table)*
`id, target_id (fk), proof_type (dns_txt/file_upload/signed_letter/cloud_iam_role), proof_reference, verified (bool), verified_by, verified_at, active_testing_allowed (bool), scope_notes, expires_at`

**assets**
`id, project_id (fk), target_id (fk), asset_type (subdomain/port/service/cloud_resource/container), value, first_seen, last_seen, metadata (jsonb)`

**scans**
`id, project_id (fk), target_id (fk), initiated_by (fk users), scan_type (web/api/network/cloud), status (queued/running/completed/failed/cancelled), ai_plan_id (fk ai_plans), started_at, completed_at, config (jsonb)`

**ai_plans**
`id, scan_id (fk), tool_sequence (jsonb), reasoning_summary, model_version, created_at`

**tool_runs**
`id, scan_id (fk), tool_name, tool_version, status, command_hash, started_at, completed_at, exit_code, raw_output_ref (pointer to object storage)`

**evidence**
`id, tool_run_id (fk), evidence_type (request_response/screenshot/log_excerpt/http_trace), storage_uri, checksum (sha256), created_at`

**vulnerabilities**
`id, project_id (fk), asset_id (fk), first_detected_scan_id (fk scans), title, category (owasp_top10_id/cwe_id), description, cvss_vector, cvss_score, severity, status (open/confirmed/false_positive/fixed/accepted_risk/reopened), ai_validated (bool), ai_confidence, created_at, updated_at`

**vulnerability_evidence** *(many-to-many: a finding can cite multiple evidence rows)*
`vulnerability_id (fk), evidence_id (fk), tool_run_id (fk)`

**remediations**
`id, vulnerability_id (fk), summary, steps (jsonb), references (jsonb), generated_by (ai/human), created_at`

**risk_scores**
`id, vulnerability_id (fk), business_impact_score, asset_criticality_weight, final_risk_score, rationale, computed_at`

**compliance_mappings**
`id, vulnerability_id (fk), framework (owasp/nist/iso27001/pci_dss/cis), control_id, control_description`

**reports**
`id, project_id (fk), type (executive/technical), format (pdf/html), storage_uri, generated_by (fk users, nullable if ai-triggered), generated_at, scan_ids (jsonb array)`

**notifications**
`id, workspace_id (fk), user_id (fk), type, payload (jsonb), read (bool), created_at`

**audit_logs** *(append-only, ideally a separate DB or write-once table with no UPDATE/DELETE grants)*
`id, workspace_id (fk), actor_user_id (fk, nullable for system), action, resource_type, resource_id, ip_address, user_agent, metadata (jsonb), created_at`

**api_keys**
`id, workspace_id (fk), name, key_hash, scopes (jsonb), last_used_at, created_at, revoked_at`

**settings**
`id, workspace_id (fk), key, value (jsonb)`

### ER relationships (textual, since we can't render a live diagram here)

```
workspaces 1─* workspace_members *─1 users
workspaces 1─* projects 1─* targets 1─* authorization_scopes
projects 1─* assets
targets 1─* scans *─1 ai_plans
scans 1─* tool_runs 1─* evidence
scans/assets *─* vulnerabilities *─* evidence (via vulnerability_evidence)
vulnerabilities 1─* remediations
vulnerabilities 1─1 risk_scores
vulnerabilities 1─* compliance_mappings
projects 1─* reports
workspaces 1─* audit_logs
```

**Trade-off called out:** storing raw tool output pointers in Postgres (`raw_output_ref`) rather than the blobs themselves keeps the relational DB small and fast; actual bytes live in MinIO/S3. This is standard for evidence-heavy systems (also simplifies retention/legal-hold policies — you can purge object storage by policy without touching relational history).

---

## 6. API Design (REST, versioned under `/api/v1`)

Auth: Bearer JWT (short-lived access + refresh token rotation) or API key for CI integrations. All endpoints require `workspace_id` scoping via the token claim, checked against RBAC permissions per route.

**Auth**
```
POST   /auth/register
POST   /auth/login
POST   /auth/mfa/verify
POST   /auth/refresh
POST   /auth/logout
POST   /auth/sso/callback
```

**Users & RBAC**
```
GET    /users/me
GET    /workspaces/{id}/members
POST   /workspaces/{id}/members/invite
PATCH  /workspaces/{id}/members/{user_id}/role
DELETE /workspaces/{id}/members/{user_id}
GET    /roles
POST   /roles
```

**Projects**
```
GET    /projects
POST   /projects
GET    /projects/{id}
PATCH  /projects/{id}
DELETE /projects/{id}
```

**Targets & Authorization Scope**
```
POST   /projects/{id}/targets
GET    /projects/{id}/targets
POST   /targets/{id}/authorization-scope        # submit ownership proof
GET    /targets/{id}/authorization-scope
POST   /targets/{id}/authorization-scope/verify # admin/automated verification step
```

**Assets**
```
GET    /projects/{id}/assets
GET    /assets/{id}
```

**Scans**
```
POST   /projects/{id}/scans            # body: target_id, scan_type, config, requested_modules
GET    /projects/{id}/scans
GET    /scans/{id}
GET    /scans/{id}/status              # poll or SSE stream
POST   /scans/{id}/cancel
GET    /scans/{id}/tool-runs
GET    /tool-runs/{id}/evidence
```

**Vulnerabilities**
```
GET    /projects/{id}/vulnerabilities?severity=&status=
GET    /vulnerabilities/{id}
PATCH  /vulnerabilities/{id}/status     # e.g. mark accepted-risk, with justification
GET    /vulnerabilities/{id}/remediation
GET    /vulnerabilities/{id}/compliance-mappings
```

**Reports**
```
POST   /projects/{id}/reports          # body: type, scan_ids, format
GET    /projects/{id}/reports
GET    /reports/{id}/download
```

**Dashboard**
```
GET    /dashboard/security-score
GET    /dashboard/vulnerability-summary
GET    /dashboard/trends?range=30d
GET    /dashboard/compliance-status
```

**Notifications**
```
GET    /notifications
PATCH  /notifications/{id}/read
```

**Settings / API Keys**
```
GET    /settings
PATCH  /settings
POST   /api-keys
GET    /api-keys
DELETE /api-keys/{id}
```

**Design notes:**
- Scan creation is asynchronous by nature (`POST /scans` returns `202 Accepted` + scan id immediately; real-time status via SSE or polling) — a full scan can run for minutes to hours, so a synchronous request/response model would time out and doesn't match the job-based domain.
- `PATCH /vulnerabilities/{id}/status` requiring a justification field is deliberate: analysts marking something "false positive" or "accepted risk" is itself a security-relevant, auditable decision.

---

## 7. AI Agent Workflow (detailed)

```
1. Target Intake
   → Orchestrator confirms authorization_scope.verified == true
   → If not verified: scan creation is blocked at the API layer (403), not just a warning

2. AI Planner
   → Input: target type, prior scan history, asset inventory, requested_modules
   → Output: ordered tool_sequence (jsonb) + reasoning_summary
   → Constraint: planner selects ONLY from a registered tool catalog; it cannot invent
     a command or tool it wasn't given access to (allowlist enforced in orchestrator,
     not just prompted for — this is the "AI never freelances" guarantee)

3. Tool Execution (Scanner Engine)
   → Each tool runs in its own hardened, resource-limited container
   → Passive/recon tools (subfinder, amass, httpx, naabu) run first
   → Active tools (nuclei, zap, sqlmap, nikto, ffuf) run only if
     authorization_scopes.active_testing_allowed == true
   → Metasploit validation runs only for confirmed findings needing exploit proof,
     and only if scope explicitly allows it — never as a blanket step

4. AI Correlator
   → Merges overlapping findings across tools (e.g. Nuclei + ZAP both flag same XSS)
   → Deduplicates against existing open vulnerabilities for the asset

5. AI Exploitability Validator
   → Reasons ONLY over structured tool evidence (request/response pairs, response
     diffs, tool confidence flags) — never over free-text speculation
   → Cannot mark something "confirmed" without a linked evidence_id

6. False-Positive Reduction
   → Cross-checks tool confidence, response behavior, and (where available)
     validation-tool corroboration before downgrading/dropping a finding
   → Every suppressed finding is logged (not silently deleted) for analyst review

7. Risk Prioritization
   → Combines CVSS (technical severity) with asset criticality + business context
     tags set by the customer (e.g. "this asset processes payments")

8. CVSS Calculation
   → Computed from tool-reported vector where possible; AI proposes a vector only
     when tools don't supply one, and flags it as AI-estimated for reviewer sign-off

9. Remediation Writing
   → Templated by vulnerability category, customized with AI using the specific
     evidence (stack, framework version, endpoint) — grounded, not generic boilerplate

10. Report Generation
    → Executive report: business language, trends, top risks, security score
    → Technical report: full evidence chain, PoC, CVSS, remediation steps, references
```

**Why gate at step 1 and again before active tools specifically:** authorization is the single highest-consequence check in this entire system — a missed gate here isn't a bug, it's potentially unauthorized computer access. Enforcing it at the orchestrator level (code) rather than only a UI checkbox or prompt instruction means it can't be bypassed by a compromised frontend, a malformed request, or an AI planner hallucination.

---

## 8. Tool Integration Plan

| Tool | Phase | Role | Notes |
|---|---|---|---|
| Subfinder, Amass | Recon (passive) | Subdomain discovery | Run first, cheap, low risk |
| httpx | Recon | Live host/tech probing | Feeds asset inventory |
| Naabu | Recon | Fast port discovery | Precedes Nmap for targeted deep scan |
| Nmap | Network | Service/version detection | Deep scan on Naabu-discovered ports only (efficiency) |
| WhatWeb, Wappalyzer | Recon | Tech stack fingerprinting | Informs which vuln checks are relevant |
| Nuclei | Vuln scanning | Template-based CVE/misconfig checks | Primary high-signal, low-noise scanner |
| OWASP ZAP | Web app testing | Active/passive web vuln scanning | Heavier; active mode gated by scope |
| Nikto | Web server | Server misconfig checks | Complementary to ZAP |
| Gobuster, FFUF | Content discovery | Hidden paths/files | Rate-limited, respects scope |
| SQLMap | Active testing | SQLi confirmation | Active-only, explicit opt-in, sandboxed |
| Metasploit | Validation only | Confirms exploitability of specific confirmed findings | Never used for open-ended scanning; invoked per-finding |

**Extensibility:** each tool is added as a `tool_runners/{name}_runner.py` implementing `run(target, config) -> RawOutput` and `parse(raw) -> CommonFindingSchema`. The orchestrator and AI planner only ever see the common schema, so new tools don't require AI prompt changes or orchestrator changes — just a registry entry.

---

## 9. Security Architecture

- **AuthN:** JWT access tokens (short TTL, ~15 min) + rotating refresh tokens; MFA (TOTP) required for admin/owner roles at minimum, optional-but-encouraged for all.
- **AuthZ:** RBAC enforced via permission checks at the route-dependency level in FastAPI (not scattered in business logic), backed by `role_permissions`. Add Postgres row-level security on `workspace_id` as defense in depth against an authz-check bug.
- **Secrets:** environment secrets and per-target credentials (e.g. cloud IAM keys for cloud scans) encrypted at rest (KMS-backed), never logged, never returned in API responses after creation.
- **Tool sandboxing:** every tool runner executes inside a locked-down container (no outbound access except to the declared target, dropped capabilities, resource/time limits) — this limits blast radius if a tool itself is exploited or misused.
- **Rate limiting:** per-user and per-workspace, both on the API gateway and specifically on active-testing tool invocation (prevents a compromised account from mass-scanning).
- **Input validation / output sanitization:** strict Pydantic schemas on every endpoint; all report/dashboard rendering treats tool output as untrusted data (escape before rendering — tool output can itself contain injection payloads reflected from the target).
- **Audit logging:** append-only, covers auth events, scope changes, scan creation/cancellation, vulnerability status changes, report exports, and API key usage.
- **Data retention:** configurable per workspace for evidence/report retention, since some enterprise customers have compliance-driven retention/deletion requirements (e.g. PCI DSS logging retention vs a customer's own data minimization policy — these can conflict and need a per-tenant setting, not a global constant).

---

## 10. Tech Stack (with reasoning)

| Layer | Choice | Why |
|---|---|---|
| Frontend | Next.js + TypeScript + Tailwind | SSR for a fast dashboard, strong ecosystem for data-heavy enterprise UIs |
| Backend | Python + FastAPI | Async-native (matters for I/O-bound scan orchestration), same language as the AI/tool-integration layer reduces context-switching for the team |
| DB | PostgreSQL | JSONB support handles flexible tool-output/config fields while keeping relational integrity for the audit-critical tables |
| Cache/Queue | Redis + Celery | Mature, well-understood job queue for long-running scan tasks; Redis doubles as cache + distributed lock for preventing duplicate scans on the same target |
| Containerization | Docker (Compose → K8s later) | Compose is enough at pilot scale; see §13 for when to graduate to K8s |
| Reverse proxy | Nginx | TLS termination, request buffering for large report downloads |
| Auth | JWT + OIDC for enterprise SSO | JWT for API-native clients, OIDC bridge for enterprise customers who mandate their own IdP |
| Object storage | MinIO (self-hosted) or S3 | Evidence/report blobs; MinIO gives on-prem/air-gapped deployment option, which enterprise security buyers often require |

---

## 11. Development Roadmap & Milestones

**Phase 0 — Foundations (2–3 weeks)**
Auth, RBAC, workspaces, projects, targets, authorization-scope gate, base CI/CD, base Next.js shell with auth flow.
*Milestone: a user can sign up, create a workspace/project, add a target, and submit ownership proof — nothing scans yet.*

**Phase 1 — Recon + First Scanner Loop (3–4 weeks)**
Scanner Engine skeleton, Celery workers, tool runners for Subfinder/httpx/Naabu/Nmap (passive/low-risk tools only), evidence store, raw findings displayed unprocessed.
*Milestone: end-to-end scan runs and produces raw asset/port findings visible in the UI, gated correctly by authorization scope.*

**Phase 2 — Vulnerability Scanning + Vuln Engine (3–4 weeks)**
Add Nuclei, ZAP, Nikto, WhatWeb; build Vulnerability Engine (dedupe, CVSS, lifecycle states); vulnerability list UI.
*Milestone: real vulnerabilities from real tools, deduped, with CVSS scores, no AI yet.*

**Phase 3 — AI Layer v1 (4–5 weeks)**
AI Planner (tool selection), Correlator, basic FP reduction, remediation writer (grounded in evidence).
*Milestone: AI adds real value on top of tool output — smarter sequencing, fewer duplicates, readable remediation text.*

**Phase 4 — Risk, Reporting, Compliance (3–4 weeks)**
Risk Engine, Compliance mapping tables, Reporting Engine (exec + technical PDF), Dashboard security score.
*Milestone: a customer can run a scan and walk away with a presentable PDF report.*

**Phase 5 — Active Testing + Validation (3–4 weeks)**
SQLMap, FFUF/Gobuster active modules, Metasploit validation-only integration, exploitability AI validator, stricter scope gating.
*Milestone: confirmed, validated (not just detected) findings with proof-of-exploit evidence.*

**Phase 6 — Enterprise Hardening (3–4 weeks)**
SSO/OIDC, audit logging completeness, scheduled scans, notifications, API keys for CI integration, cloud security modules (AWS/Azure/GCP IAM + storage bucket checks).
*Milestone: platform meets baseline enterprise procurement checklist (SSO, audit trail, RBAC, scheduled scans).*

**Phase 7 — Scale & Polish**
Performance tuning, K8s migration if load warrants it (see §13), UI polish to enterprise dashboard bar, container security (Docker/K8s scanning modules).

---

## 12. Implementation Order (concrete build sequence for Claude Code sessions)

1. Repo scaffold + Docker Compose (Postgres, Redis, MinIO, api, web) — get "hello world" round-tripping first.
2. Auth + RBAC + workspaces/projects/targets models + migrations.
3. Authorization-scope submission + verification flow (build this before any scanner — it's the gate everything else depends on).
4. Scanner orchestrator skeleton + one tool runner (Naabu is a good first one — simple, fast, structured output) end-to-end through to a vulnerabilities-adjacent "assets" table.
5. Add remaining recon tools using the same adapter pattern (proves the extensibility model works before you're 10 tools deep).
6. Vulnerability Engine + first vuln-producing tool (Nuclei) + vulnerability UI.
7. Evidence store wiring (screenshots, raw output linkage) — retrofit onto steps 4–6 if needed.
8. AI Planner + Correlator (start here once there's real multi-tool output to correlate — building AI before there's real data to reason over just produces mocked demos).
9. Risk Engine + CVSS + Compliance mapping.
10. Reporting Engine (PDF generation) — big enterprise-visible milestone, prioritize once findings are trustworthy.
11. Remediation writer + FP reducer refinement.
12. Active testing tools + Metasploit validation, with extra scope-gate tests.
13. Dashboard aggregations, notifications, scheduled scans.
14. SSO, audit log completeness pass, API keys, hardening review.

---

## 13. Future Expansion Plan

- **Service decomposition:** once scan volume justifies it, split Scanner Engine and AI Agent into independently deployed services (they already have clean boundaries via the modular monolith structure) and move to Kubernetes for independent autoscaling of scan workers vs API pods.
- **Multi-region deployment:** for enterprise customers with data-residency requirements, evidence/report storage should be regionalizable per workspace.
- **Plugin marketplace:** the tool-runner adapter pattern generalizes into a plugin SDK, letting customers/partners contribute new tool integrations without core code access.
- **Continuous monitoring mode:** shift from scan-triggered to always-on lightweight monitoring (scheduled diff-based rescans) for asset/attack-surface drift detection.
- **Additional compliance frameworks:** SOC 2, HIPAA, FedRAMP mappings as customer base grows into regulated industries.
- **On-prem/air-gapped edition:** given MinIO + Docker Compose base, an air-gapped deployment package is a natural enterprise upsell for customers who can't send data to cloud-hosted AI.

---

## Decisions Locked (2026-07-23)

1. **LLM provider/model:** Anthropic Claude, via the Anthropic API. `ai_agent/` is built directly against Claude (no provider-abstraction overhead) — planner, correlator, validator, remediation writer, and report writer all call Claude.
2. **Multi-tenancy:** shared schema with `workspace_id` + Postgres row-level security, as assumed in §5. Revisit only if a specific enterprise buyer contractually requires DB-per-tenant isolation.
3. **On-prem/air-gapped:** deferred past launch. v1 ships S3-only for object storage; MinIO compatibility is kept in mind (same S3 API) so an air-gapped package remains a future upsell (§13) without a rewrite.
4. **Cloud Security module (Phase 6) v1 scope:** AWS only. Azure/GCP support is a later-phase addition, not launch-blocking.

## Step 2 Implementation Notes (2026-07-24)

Auth, RBAC, workspaces, projects, and targets are built (`apps/api/modules/{auth,users,workspaces,projects}`), migrated via Alembic (`87ca3d89a924` schema + `6a99a2128bba` RBAC seed), and verified end-to-end against live Postgres (register → login → create workspace → create project → add target, plus cross-tenant denial and role-restriction checks). A few real deviations/decisions from §6 worth recording so they don't look like drift later:

- **Workspace scoping is a path parameter, not a token claim.** §6 said "workspace_id scoping via the token claim," but nothing in §6/§7 defines a workspace-switching login flow, and a JWT issued at login can't encode "the" workspace for a user who belongs to several. Implemented instead as `/workspaces/{workspace_id}/...` for every workspace-scoped resource (projects, targets, members) — consistent with how §6 already nested the members endpoints — resolved by `core/deps.get_workspace_context`, which checks membership and sets a Postgres session var for RLS in the same step. If a workspace-switcher UX gets designed later, a token claim can be layered on top without changing the DB layer.
- **`POST /workspaces` and `GET /workspaces` were added.** §6 never listed a workspace-creation endpoint, but the Phase 0 milestone ("a user can sign up, create a workspace/project...") requires one. Creator becomes `owner`.
- **Row-level security is implemented, not just planned.** `workspace_members`, `projects`, and `targets` all have `ENABLE` + `FORCE ROW LEVEL SECURITY` with a policy keyed on `current_setting('app.current_workspace_id', true)`. `FORCE` matters here specifically because the app connects as the same role that owns the tables (single-role pilot setup) — Postgres exempts table owners from RLS by default, so without `FORCE` the policies would silently no-op for every real request.
- **Refresh tokens are stored server-side (hashed) and rotate on use** (`refresh_tokens` table, sha256 of the token, `replaced_by_id` chain) rather than being purely stateless, so `POST /auth/logout` and theft-detection (a reused, already-rotated token) are both possible later.
- **Deferred, not built:** `POST /auth/mfa/verify`, `POST /auth/sso/callback` (no phase in §11 assigns MFA verification; SSO is explicitly Phase 6), `POST /roles` (custom per-workspace roles need a permission-assignment endpoint to be useful, which doesn't exist yet — only the three seeded system roles `owner`/`admin`/`member` exist), and a pending-invite/email-token flow for `POST /workspaces/{id}/members/invite` (it currently adds an *already-registered* user to the workspace immediately — no invite email, since that's the Notification Service, a later phase).
- **Permission keys seeded so far:** `workspace:view`, `workspace:manage`, `project:{create,read,update,delete}`, `target:{create,read,delete}` (`db/migrations/versions/6a99a2128bba_*.py`). Extend this list alongside each future module rather than front-loading permissions for features that don't exist yet.

## Step 3 Implementation Notes (2026-07-24)

The authorization-scope gate is built (`apps/api/modules/authorization_scope`), migrated (`90c242a2cfe1` schema/RLS + `eaf57eef76d7` permission seed), and verified end-to-end. It follows the same nested-path pattern as step 2: `/workspaces/{workspace_id}/projects/{project_id}/targets/{target_id}/authorization-scope`.

- **`verified` is real, not decorative — but the underlying proof-checking is still human/manual, not automated.** §7 says the orchestrator must confirm `authorization_scope.verified == true` before anything active runs; that orchestrator doesn't exist yet (Phase 1+), so step 3's job was building the gate's data model and API correctly so Phase 1 has something real to check. `POST .../authorization-scope` always creates a fresh row with `verified=false, active_testing_allowed=false` — submitting proof never self-grants anything. Only `POST .../authorization-scope/verify` can flip `verified` to true, and it's a separate, more restricted permission (`authorization_scope:verify`, seeded **owner-only** — not admin, not member) from submission (`authorization_scope:submit`, open to owner/admin/member like `target:create`). The reasoning: letting the same account that submitted a claim also certify it defeats the point of the gate.
- **Known-imperfect stopgap:** because there's no independent reviewer role or automated proof-checking yet (real DNS TXT lookups, file-existence checks, cloud IAM role assumption — all deferred; they start to overlap with Phase 1 recon tooling and, for file/URL fetching specifically, need SSRF-safe handling before they touch arbitrary user-supplied URLs), a workspace owner can still self-verify their own submission today. Restricting `verify` to `owner` only is a minimal safeguard, not a real independent-review guarantee. Revisit when Phase 1's orchestrator starts consuming this gate for real.
- **History is preserved, not overwritten.** Matches the ER diagram's `targets 1─* authorization_scopes` (one-to-many, not one-to-one): every `POST .../authorization-scope` inserts a new row rather than updating in place, so a rejected/expired submission's evidence trail survives resubmission. `GET .../authorization-scope` returns the most recent row for the target; there's no "list history" endpoint yet since nothing consumes it (added when the Audit Logging module, Phase 6, needs it).
- **Two-hop RLS.** `authorization_scopes` has no `workspace_id` column of its own (per the blueprint's schema) — its RLS policy joins through `targets → projects.workspace_id`, same `ENABLE`+`FORCE ROW LEVEL SECURITY` pattern as step 2, verified with the same non-member-gets-403 style check.
- **`created_at` was added** to the `authorization_scopes` table (not in the original §5 column list) — needed to order submissions and determine "latest" now that history is preserved. Every other table already had one.

## Step 4 Implementation Notes (2026-07-26)

First real scanner loop is built and verified live: a scan against a container we control (`nginx`) ran Naabu, stored raw output as evidence in MinIO, and produced a `port` asset — gated correctly by the step 3 authorization scope. Modules: `apps/api/modules/scans`, `apps/api/modules/assets`, `apps/api/scanner_engine/*`, `apps/api/celery_app/tasks/scan_tasks.py`. Migrations `35da883cdec8` (tables + RLS) and `baf7c3543732` (permission seed).

- **The authorization gate is now actually enforced, in two places.** `authorization_scope.service.require_verified_target` is called both at scan creation (HTTP → 403 if the target has no verified, unexpired scope) and again inside the orchestrator right before tools run (authorization can be revoked/expire between queue and execution — blueprint §7). This is the payoff for step 3 existing.
- **`scans` is deliberately NOT under RLS; everything else in this step is.** The Celery worker has no HTTP `{workspace_id}` path param to bootstrap the RLS session var from, and `projects`/`targets` are FORCE-RLS — so it can't even read them to *discover* the workspace. Resolution: `scans` carries a denormalized `workspace_id` and is RLS-exempt, so the worker reads one scan row by trusted (internally-generated, never client-supplied) id, then sets `app.current_workspace_id` itself before touching anything else. `assets`, `tool_runs`, and `evidence` all get the usual `ENABLE`+`FORCE ROW LEVEL SECURITY` (2- and 3-hop policies through `projects`/`scans`).
- **Worker DB engine specifics (two real bugs found and fixed live):** (1) the worker builds a *fresh* async engine per task — reusing the API's module-level engine hits "Future attached to a different loop" because Celery runs each task under a new `asyncio.run()` loop. (2) That engine uses `StaticPool` (one persistent connection) because the orchestrator sets the RLS GUC once (session-level) then commits several times; with a normal pool each commit returns the connection and the next op could get a different one *without* the GUC — FORCE RLS would then block the worker's own writes.
- **`models_all.py` added.** Any process that touches the ORM without importing the FastAPI routers (the Celery worker; Alembic `env.py`) must import every model module first, or cross-module FKs fail to resolve (`NoReferencedTableError: ...'scans.initiated_by' could not find table 'users'`). Both the worker and `env.py` now import `apps/api/core/models_all.py`; new model modules get registered there in one place.
- **Tool-runner adapter pattern is real (blueprint §4/§8).** `scanner_engine/tool_runners/base.py` defines `BaseToolRunner` (`run()` → `RawToolOutput`, `parse()` → `list[CommonFinding]`); `tool_registry.py` maps `"naabu"` → `NaabuRunner`. Adding a tool = new runner file + one registry entry; the orchestrator, API validation, and (later) AI planner only ever see `CommonFinding`. Naabu is pinned to 2.6.1 in both `NaabuRunner.version` and the worker Dockerfile `ARG NAABU_VERSION`.
- **Naabu DNS gotcha.** ProjectDiscovery tools use their own bundled resolvers, which bypass the OS resolver — so Docker-internal names (and any internal/split-horizon DNS) don't resolve. The runner resolves the host via the OS (`socket.getaddrinfo`) itself and hands Naabu an IP; IPs/CIDRs pass through untouched. Scans run `-scan-type connect` (no root/raw sockets); `libpcap0.8` is installed for future `-scan-type syn`.
- **Assets are upserted, not duplicated.** Re-scanning updates `last_seen`/`metadata` on the `(target_id, asset_type, value)` unique key (assets outlive scans, §3). Uses `pg_insert(Asset.__table__)` — targeting `.__table__`, not the mapped class, because `metadata` on a declarative class is SQLAlchemy's `MetaData` object, not the column (attribute is `metadata_`).
- **Deferred:** `GET /scans/{id}/status` as SSE (only polling `GET /scans/{id}` exists — SSE waits until there's a UI to consume it); the AI planner deciding the tool sequence (Phase 3 — for now `requested_modules` in the request body drives it directly); `ai_plan_id` on scans (the `ai_plans` table is Phase 3). Naabu is the only registered tool; the remaining recon tools (subfinder/httpx/amass) are the next build-order item.

## Step 5 Implementation Notes (2026-07-26)

The remaining recon tools — **Subfinder, httpx, Nmap** — are added via the same adapter pattern and wired into a **light deterministic recon pipeline**. Verified live: a single scan against the `nginx` container ran all four tools in phase order and chained their output (httpx probed the target → naabu found port 80 → nmap deep-scanned *that* port and fingerprinted it as `http`/`nginx`). No migration (recon tools only emit new `asset_type` strings into the existing `assets` table; `scan:*`/`asset:read` already cover them).

- **Deterministic pipeline via `phase`.** `BaseToolRunner` gained a `phase: int`; the orchestrator sorts requested modules by phase (subfinder 10 → httpx 20 → naabu 30 → nmap 40) and ignores request order. Confirmed live by requesting `["nmap","naabu","httpx","subfinder"]` and observing execution in the correct order. Intelligent/target-aware sequencing is still the AI Planner's job (step 8); this ordering is fixed.
- **Intra-scan finding passing.** `run()` now takes `prior_findings: list[CommonFinding]` — the orchestrator accumulates findings and threads them through the chain, so each runner builds on earlier ones: httpx probes subfinder's `subdomain`s (+ the target); naabu scans httpx-confirmed live hosts (falls back to subdomains, then the bare target); nmap deep-scans exactly naabu's `port` findings (falls back to `--top-ports` on the target). Empty `prior_findings` = run against the target alone, so behavior is unchanged when a tool runs solo.
- **`applicable_target_types`.** Optional per-runner set (None = all); the orchestrator *skips* a requested runner cleanly when the target `type` doesn't match, rather than running it and recording a failure. Subfinder is `{"domain"}` — requesting it on an `ip_range` target is a no-op, not a failed tool_run.
- **Emitted asset types:** subfinder → `subdomain`, httpx → `http_service` (metadata: host/port/scheme/status_code/title/webserver/tech), naabu → `port` (unchanged), nmap → `service` (metadata: service/product/version/protocol).
- **Shared DNS resolver helper.** The in-process OS-resolve workaround (§Step 4) is extracted to `scanner_engine/tool_runners/_net.py` (`resolve_scan_host`) and reused by naabu, httpx, and nmap. Subfinder needs no resolution (passive enumeration of a domain name).
- **httpx binary renamed to `httpx-pd`.** The Python `httpx` library is on PATH in the worker; the ProjectDiscovery binary is installed as `/usr/local/bin/httpx-pd` and invoked by that name to avoid any collision. Nmap runs `-sT -sV -Pn` (connect scan, version detection, skip host discovery — containers often drop ping), parsed from `-oX -` XML via stdlib `xml.etree`. Versions pinned in both each runner's `.version` and the Dockerfile `ARG`s (subfinder 2.14.0, httpx 1.10.0, naabu 2.6.1, nmap from apt = 7.95).
- **Known limitation:** because hosts are OS-resolved to IPs before probing (the resolver workaround), httpx/nmap probe by IP and lose virtual-host (Host header) routing — fine for IP-addressable services and the internal test target, but multi-vhost HTTPS targets would need hostname-based probing later (revisit when a real resolver-config path exists). Active-testing enforcement (`active_testing_allowed` for nuclei/sqlmap) remains deferred to phase 5; all step-5 tools are passive.
