# MBS.PT (formerly MBS.SC)

A multi-tenant platform for automated security assessment that treats an AI-generated finding
as a hypothesis requiring evidence, not as a result to be trusted.

---

## The problem

Automated security assessment driven by large language models produces findings quickly, and
that is precisely the difficulty: a model can describe a vulnerability fluently whether or not
it exists. The same problem predates LLMs in a milder form — a scanner template match is a
pattern match, not a demonstration — but an LLM makes it worse, because its output is
persuasive, self-confident, and cheap to generate at volume.

The open question this project is built around is therefore:

> **When an automated agent reports a vulnerability, what would it take to believe it?**

A system that cannot answer this produces output an analyst has to re-verify by hand, which
removes most of the value of automating the assessment. Two failure modes matter, and they
pull in opposite directions: reporting something that is not real (false positive, wasted
analyst time, eroded trust), and suppressing something that is (false negative, the more
dangerous error in a security context).

The position taken here is that a model's own confidence is not admissible evidence for its own
claim. Consequently the system separates three things that are easy to conflate:

| Question | Answered by | Where |
|---|---|---|
| Did a tool or model flag this? | the scanner / AI enrichment | `scanner_engine/`, `ai_agent/` |
| How sure is the model about its own output? | `vulnerabilities.ai_confidence` | `ai_agent/` |
| Was the condition actually **demonstrated**? | evidence-based verification state | [`modules/reports/verification.py`](apps/api/modules/reports/verification.py) |

The third is deliberately never derived from the second. The verification classifier reaches
`VERIFIED` only through an explicit positive evidence signal — never from a template name, a
severity, a CVSS score, or a model's self-rating.

### Design commitments that follow from this

- **Fail toward "unproven", not toward "safe-looking".** Verification defaults to `UNVERIFIED`
  and can only be raised by evidence. The finding classifier fails the opposite way — toward
  "this is a vulnerability" — so that neither error direction is systematically hidden.
- **Verification never edits severity.** An unverified CVSS 9.8 remains a CVSS 9.8. Downgrading
  unproven findings would quietly bury real risk, so the report states proof and severity side
  by side and leaves prioritisation to the analyst.
- **The AI cannot invent actions.** The planner's output is filtered against the tool registry,
  the user's requested modules, the target type, and the authorization state. It may reorder
  and prune within those bounds; it cannot introduce a tool. See `_sanitize` in
  [`ai_agent/planner.py`](apps/api/ai_agent/planner.py).
- **Proof attempts are bounded and non-destructive.** An exploit-confirmation module declares a
  single benign `proof_action`, must never modify, delete, persist or exfiltrate, and must
  return redacted proof ([`scanner_engine/exploits/base.py`](apps/api/scanner_engine/exploits/base.py)).

---

## Architecture

The pipeline is a deterministic tool chain with AI components attached at specific points,
rather than an agent loop given free rein. Each AI stage has a code-enforced boundary.

```mermaid
flowchart TD
    A[Scan request] --> B{Authorization scope<br/>verified?}
    B -- no --> BX[Refused: no scan runs without<br/>proven target ownership]
    B -- yes --> C[AI Planner]

    C --> D[_sanitize<br/>registry + scope + target type<br/>+ active-testing gate]
    D --> E[Deterministic tool chain<br/>subfinder &rarr; httpx &rarr; naabu &rarr; nmap<br/>&rarr; katana &rarr; nuclei · 12 registered tools]

    E --> F[(Raw output<br/>MinIO / S3<br/>checksummed)]
    E --> G[Findings]

    G --> H[AI Correlator<br/>groups related findings]
    H --> I[AI FP Reducer<br/>flags likely false positives]

    G --> J[Exploit modules<br/>single benign proof action<br/>non-destructive, redacted proof]
    J --> K[(Evidence<br/>excerpts · screenshots)]

    I --> L[Verification classifier]
    K --> L
    F --> L

    L --> M{Evidence present?}
    M -- positive proof --> N[VERIFIED]
    M -- artefacts only --> O[PARTIALLY_VERIFIED]
    M -- pattern match only --> P[UNVERIFIED]

    N --> Q[Report writer<br/>deterministic, no LLM<br/>wording gated on verification state]
    O --> Q
    P --> Q
    Q --> R[Assessment report]

    style BX fill:#fff0f0,stroke:#c0392b
    style N fill:#eafaf1,stroke:#27ae60
    style P fill:#fdf6e3,stroke:#b7950b
    style Q fill:#eef3fa,stroke:#2c6fbb
```

A note on naming, since it differs from a conventional four-agent layout: the AI stages that
exist are **Planner**, **Correlator**, **FP Reducer**, a **RedTeamAgent** (candidate action
ranking) and an **Assistant** (in-product explanation). There is deliberately **no LLM report
writer** — report narrative is produced by a pure, deterministic function of finding metadata
([`modules/reports/narrative.py`](apps/api/modules/reports/narrative.py)) whose impact language
is gated on verification state, so that only a `VERIFIED` finding may use confirmatory
phrasing. Generating the final security report with a language model would reintroduce exactly
the unverifiable-claim problem the rest of the system exists to remove.

---

## Tech stack

| Layer | Technology |
|---|---|
| API | FastAPI 0.141 (modular monolith, 25 modules), Python 3.12 |
| Database | **MySQL 8** with SQLAlchemy 2.0 async (`aiomysql`/`PyMySQL`) + Alembic (19 migrations) |
| Async work | Celery 5.4 + Redis (8 task groups, incl. Celery beat schedules) |
| Object storage | MinIO (S3 API via boto3) — raw tool output and evidence artefacts |
| Frontend | Next.js 15.5, React 18, TypeScript 5.6, Tailwind; dependency-free i18n, 7 locales incl. RTL Arabic |
| AI | Anthropic Claude behind a provider interface (`anthropic`, `openrouter`, `deepseek`, local/Ollama, fallback) |
| Infra | Docker Compose (`mysql`, `redis`, `minio`, `api`, `worker`, `beat`, `web`, `nginx`, `scanner-manager`) |
| Security tooling | subfinder, amass, dnsx, httpx, whatweb, naabu, nmap, katana, ffuf, arjun, nuclei, nuclei-dast |

> **On the database:** this project runs on **MySQL 8, not PostgreSQL.** The cutover is
> load-bearing for the security model rather than incidental: MySQL has no row-level security,
> so tenant isolation is enforced in the application layer by an ORM-level workspace filter
> applied to every query on every tenant table ([`core/tenancy.py`](apps/api/core/tenancy.py)),
> keyed on a per-request workspace held in a `contextvars` context. Raw SQL bypasses that
> filter, which is why every raw statement is registered and CI-gated (see below).

---

## Current status

Verified against the code and the test suite at the time of writing. Nothing below is aspirational.

### Implemented and working

- **Evidence-based verification** — three-state classifier (`VERIFIED` / `PARTIALLY_VERIFIED` /
  `UNVERIFIED`) with confidence tracked separately; fails safe toward unverified.
- **Deterministic tool chain** — 12 registered tools with explicit phase ordering, capability
  tags and active-testing flags; each stage feeds the next.
- **Authorization gate** — no scan runs without verified proof of target ownership;
  payload-sending tools run only when the scope explicitly authorizes active testing.
- **AI stages with enforced boundaries** — Planner, Correlator, FP Reducer, RedTeamAgent,
  Assistant. All degrade gracefully: with no API key the system runs without AI.
- **Multi-tenancy** — shared-schema workspace isolation enforced at the ORM layer, RBAC
  (owner/admin/member), workspace API keys, append-only audit log.
- **Reporting** — deterministic PDF assessment reports; narrative wording gated on verification
  state; evidence integrity checked.
- **Supporting subsystems** — vulnerability lifecycle and dedup, risk scoring (CVSS weighted by
  asset criticality), compliance mapping, remediation catalogue, scheduled scans, notifications,
  plan/usage enforcement, GDPR tenant export and erasure, DR backup/restore.
- **Security engineering controls in CI** — raw-SQL inventory gate (39 registered statements,
  fails on drift), secret scanning, dependency audit (pip-audit), SBOM, container image scan,
  blocking `ruff` + `mypy`, blocking frontend typecheck/lint/test/build.
- **Test suite** — 4,626 tests across 234 files.

### Partial / in progress

- **Exploit confirmation modules** — the framework, safety contract and audit trail are in
  place; two concrete modules exist (`DefaultCredentialsValidator`, `KnownCveValidator`). The
  set of finding classes that can be positively proven is therefore still narrow, so most
  findings resolve to `PARTIALLY_VERIFIED` or `UNVERIFIED` rather than `VERIFIED`. Widening
  this coverage is the main line of active work.
- **Frontend i18n** — 7 locales present; some namespaces (remediation, assessment, assets) are
  not yet fully translated and fall back to English.
- **Branch state** — the default branch `main` does not yet include the most recent work
  (reporting redesign, remediation catalogue, product rename); that work sits on
  `chore/untangle-phase0`.

### Known limitations

- **Scanner-tool CVEs** — the scanner-tool container still reports CRITICAL CVEs originating
  in the Go dependencies that upstream statically links into its release binaries: `dnsx`,
  `naabu` and `subfinder` (Go stdlib `crypto/tls`, CVE-2025-68121) and `katana`
  (`github.com/jackc/pgx/v5`, CVE-2026-33815 / CVE-2026-33816). The fix is not ours to apply —
  it lands when each tool's maintainers rebuild against the patched module — so these are
  individually triaged in `.trivyignore` with the reason each is not reachable in this image,
  pending a tool-version upgrade. The CRITICAL gate itself stays active: any CVE **not** on
  that list still fails CI.

### Not implemented (explicitly out of scope so far)

- Payment processing (plan enforcement exists; no payment processor is wired in).
- Webhook and email notification channels (in-app notifications only).
- SSO / SAML / OIDC.
- There is no `TestPlan` or attack-surface knowledge-graph subsystem; those appear in design
  documents as a target architecture, not as shipped code.

---

## Quick start

Requires Docker Desktop (Compose v2). Nothing else is needed to run the stack.

```bash
cp .env.example .env          # Windows: copy .env.example .env

docker compose -f infra/docker-compose.yml -f infra/docker-compose.override.yml up --build -d

docker compose -f infra/docker-compose.yml -f infra/docker-compose.override.yml \
  exec api sh -c "cd /srv/db && alembic upgrade head"
```

Then open:

| Service | URL |
|---|---|
| App (landing + dashboard) | http://localhost |
| API health / interactive docs | http://localhost:8000/health · http://localhost:8000/docs |
| MinIO console | http://localhost:9001 (`minioadmin` / `minioadmin`) |

Use `localhost` rather than `127.0.0.1` or a LAN IP, so the browser's CORS origin matches the
API allow-list.

> **Always pass both `-f` files in development.** Compose merges `docker-compose.override.yml`
> automatically only when no `-f` is given, so an explicit `-f` list must name it. The override
> carries hot reload, the `localhost:8000` port and the `apps/api` code bind mount. Omitting it
> does not fail loudly — the container would otherwise serve the code baked into the image at
> its last build. The API guards against this: it refuses to start when the stack mode is
> `unconfigured` (see [`core/stack_mode.py`](apps/api/core/stack_mode.py)). Equivalently, run
> `cd infra && docker compose up -d`.

### Enabling AI (optional)

The platform runs fully without an API key; AI stages degrade gracefully. To enable them:

```bash
# in .env
ANTHROPIC_API_KEY=sk-ant-...

docker compose -f infra/docker-compose.yml -f infra/docker-compose.override.yml up -d api worker
```

### Running the tests

The suite **wipes every table in the target database**, so it refuses to run unless the target
database name ends in `_test`. Point it at a dedicated database:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.override.yml exec -T api \
  sh -c 'cd /srv && DATABASE_URL="mysql+aiomysql://mbs:mbs@mysql:3306/mbs_test" \
         python -m pytest apps/api/tests -q'
```

Frontend checks:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.override.yml exec web npx tsc --noEmit
docker compose -f infra/docker-compose.yml -f infra/docker-compose.override.yml exec web npm test
```

---

## Open research questions

These are the questions the system is built to investigate; it does not claim to have settled them.

1. **What constitutes sufficient evidence for an automated finding?** The current answer is a
   three-state classifier driven by captured artefacts, with `VERIFIED` reachable only through
   positive proof. This is a defensible engineering default, not a validated epistemic standard.
   Which artefact types genuinely justify belief, and for which vulnerability classes, is open.

2. **How far can proof-of-exploit be automated without becoming destructive?** Every proof
   action must be non-destructive, single-step and redacted. That constraint bounds which
   finding classes can ever be positively verified — a stored-XSS or a business-logic flaw may
   be unprovable under it. Where the ceiling sits is unresolved.

3. **Can false-positive reduction be evaluated without ground truth?** An FP reducer that
   suppresses a true positive causes more harm than the noise it removes, yet in a live
   assessment there is rarely a labelled answer key to measure against. This system keeps the
   AI's judgement advisory and separate from verification state, deferring rather than solving
   the problem.

4. **Are LLM security agents trustworthy enough to act, or only to suggest?** The current
   architecture answers "suggest": the planner may reorder and prune within a registry, never
   introduce an action, and the report is written by deterministic code. Whether a stronger
   delegation can be made safe — and what evidence would justify it — is the broader question.

5. **How should unverified findings be presented?** Severity is deliberately not reduced for
   unproven findings, to avoid hiding real risk. Whether analysts read a high-severity
   `UNVERIFIED` finding as urgent or as noise is an empirical human-factors question.

---

## Ethical use

This software performs active security testing, including payload-sending tools and bounded
exploit-confirmation attempts. Use it **only against systems you own or are explicitly
authorized in writing to test.**

The platform enforces this structurally rather than by policy alone: no scan runs without
verified proof of target ownership, and payload-sending tools are gated behind an explicit
active-testing authorization on the scope. These controls exist to make unauthorized use
difficult; they do not transfer legal responsibility. Unauthorized scanning is illegal in most
jurisdictions, and the author accepts no liability for misuse.

---

## Repository layout

- `apps/api` — FastAPI backend: `modules/` (25 feature modules), `ai_agent/`, `scanner_engine/`,
  `celery_app/`, `core/`
- `apps/web` — Next.js dashboard and landing page (`app/`, `components/`, `locales/`, `lib/`)
- `infra/` — Dockerfiles, nginx, Docker Compose files
- `db/` — Alembic migrations
- `docs/architecture/` — design documents and the dated implementation log

---

## Author

**Bandar Oudah H. Alkhaldi**
Bachelor of Cybersecurity, Lincoln University College
bandaraodh@gmail.com

## License

[MIT](LICENSE)
