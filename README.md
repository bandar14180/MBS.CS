# MBS.SC — Autonomous AI Cybersecurity Platform

**Autonomous AI agents for next-generation cybersecurity.** MBS.SC discovers vulnerabilities, analyzes risk, and automates penetration testing across web, API, cloud, and network — as a multi-tenant SaaS.

> Full architecture, data model, and decision log: [docs/architecture/blueprint.md](docs/architecture/blueprint.md).

---

## What it does

- **AI-orchestrated scanning** — a deterministic recon pipeline (subfinder → httpx → naabu → nmap → nuclei) where each tool feeds the next, with an optional **AI Planner** that reorders/prunes the toolset.
- **Fail-fast pipeline** — any tool failure aborts the scan immediately; the scan is marked `failed`, the exact error is captured, and **no report is generated** over a failed assessment.
- **Evidence-backed findings** — every finding traces to raw tool output stored in object storage (checksummed).
- **Vulnerability engine** — dedup + lifecycle (open / confirmed / false-positive / fixed / accepted-risk / reopened), with audited triage.
- **Risk engine** — CVSS weighted by asset criticality.
- **Compliance mapping** — findings mapped to **OWASP · NIST 800-53 · ISO/IEC 27001 · PCI DSS · CIS** controls.
- **AI Security Assistant** — in-product chat to explain a finding, its risk, and how to fix it.
- **Professional reports** — executive & technical PDFs (CVSS, evidence, remediation, compliance coverage).
- **Continuous security** — recurring **scheduled scans** (Celery beat) + in-app **notifications/alerts** on completion and new critical findings.
- **Commercial SaaS** — Free / Professional / Enterprise **plans with usage limits** (402 enforcement), per-workspace usage dashboard.
- **Enterprise** — shared-schema multi-tenancy with **Postgres row-level security (FORCE)** on every tenant table, RBAC (owner/admin/member), authorization-scope ownership gate, an **append-only audit log**, and **workspace API keys** for programmatic access.
- **Global** — premium landing page + full dashboard in **7 languages** (English, Arabic (RTL), Malay, French, Portuguese, Italian, Spanish).

## Security model (highlights)

- **Authorization-first**: no scan runs without verified proof of target ownership.
- **Tenant isolation**: RLS `ENABLE` + `FORCE` on every tenant table, keyed on a per-request session GUC.
- **Active-testing gate**: payload-sending tools (nuclei) run only when the scope explicitly authorizes it.
- **Audit trail**: security-relevant actions (scan created, finding triaged, plan changed) are logged immutably per workspace.

## Tech stack

- **Backend** — FastAPI (modular monolith), SQLAlchemy 2.0 async + asyncpg, Alembic, Celery + Redis, boto3 + MinIO (S3).
- **Frontend** — Next.js 14 (App Router), TypeScript, Tailwind; dependency-free i18n with RTL.
- **AI** — Anthropic Claude (`claude-opus-4-8`) behind an injectable interface (mockable-first; graceful 503 when no key).
- **Infra** — Docker Compose: `postgres`, `redis`, `minio`, `api`, `worker`, `beat`, `web`, `nginx`.
- **Security tools** — subfinder, httpx, naabu, nmap, nuclei (pinned in the worker image).

## Prerequisites

- Docker Desktop (Compose v2). Node 20+ / Python 3.12+ only needed to run outside Docker.

## Run it

```bash
cp .env.example .env          # (Windows: copy .env.example .env)
docker compose -f infra/docker-compose.yml up --build -d
docker compose -f infra/docker-compose.yml exec api sh -c "cd /srv/db && alembic upgrade head"
```

- **App (landing + dashboard)** — http://localhost  (also http://localhost:3000)
- **API** — http://localhost:8000/health · interactive docs at http://localhost:8000/docs
- **MinIO console** — http://localhost:9001 (minioadmin / minioadmin)

> Use `localhost` (not `127.0.0.1` / LAN IP) so the browser's CORS origin matches the API allow-list.

### Enable live AI (optional)

Everything works without AI (graceful fallback). To activate the AI Planner / Correlator / FP-Reducer / Remediation / Assistant, put a key in `.env` and recreate the API/worker:

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
docker compose -f infra/docker-compose.yml up -d api worker
```

### Try a scan

Register → create a project → add a target (e.g. `scanme.nmap.org`, type `domain`) → **submit + verify** ownership scope → run a scan with `subfinder, httpx, naabu, nmap`. Watch the live staged progress; generate a report when it completes.

## Tests

```bash
docker compose -f infra/docker-compose.yml exec api pytest apps/api/tests -q      # backend (96 tests)
docker compose -f infra/docker-compose.yml exec web npx tsc --noEmit              # frontend typecheck
docker compose -f infra/docker-compose.yml exec web node scripts/check-i18n.js    # 7-language parity
```

## Layout

- `apps/web` — Next.js dashboard + landing (`app/`, `components/`, `locales/`, `lib/`)
- `apps/api` — FastAPI backend: `modules/` (auth, workspaces, projects, scans, vulnerabilities, risk, compliance, reports, assistant, billing, schedules, notifications, audit, dashboard), `ai_agent/`, `scanner_engine/`, `celery_app/`
- `infra/` — Dockerfiles, nginx, docker-compose (`api`, `worker`, `beat`, `web`, …)
- `db/` — Alembic migrations
- `docs/architecture/blueprint.md` — source of truth for architecture + a dated implementation log

## Roadmap (deferred)

- Payment processor (Stripe) behind the existing plan-enforcement seam.
- Webhook/email notification channels (in-app alerts are done).
- SSO (SAML/OIDC). Workspace API keys are done.
