# MBS — Full Codebase Security Toolchain Forensic Analysis (Read-Only)

**Scope of this analysis:** `E:\MBS` (FastAPI backend `apps/api`, Next.js frontend `apps/web`, Celery workers, Docker infra). No code was modified, fixed, or refactored. All conclusions are traced to specific files/lines, or explicitly flagged as unconfirmed.

---

## A. Executive Summary

**Direct answer to the main question:** Katana does not actually produce "vulnerability reports." Structurally, **only two of the twelve registered tools — `nuclei` and `nuclei-dast` — are capable of producing a vulnerability finding at all.** Katana, subfinder, amass, dnsx, httpx, whatweb, naabu, nmap, ffuf, and arjun are recon/inventory tools: their `parse()` methods only ever return `CommonFinding` (asset) objects — subdomains, open ports, live URLs — which are written to a separate `assets` table, never to `vulnerabilities`. The Executive Report you attached (`MBS.SC — Executive Security Report`, findings like "Time-Based Blind SQL Injection" and "Command Injection — Generic Detection") is generated exclusively from the `vulnerabilities` table (`apps/api/modules/reports/data.py`), so by design it can only ever contain nuclei/nuclei-dast output — never Katana's.

So if what you're observing is "Katana's output is visible somewhere, and nuclei's/nmap's/etc. isn't," the honest breakdown is:

1. **By design (not a bug):** Katana/subfinder/httpx/naabu/nmap/whatweb/ffuf/arjun/amass/dnsx will never appear as "vulnerability findings" in the Executive/Technical report — only nuclei and nuclei-dast can. This is Possibility A/§14 (tool-specific expectations), not a defect.
2. **A real, code-confirmed frontend gap:** the scan-progress pipeline widget (`apps/web/components/project/ScanProgress.tsx`) hardcodes an 8-tool list that **omits `amass`, `dnsx`, `whatweb`, and `ffuf`** entirely — those tools' `ToolRun` rows are fetched by the component but never rendered, even if they ran successfully and found things. This is Possibility E (stored but not displayed) — **Confirmed** from the code.
3. **A concrete, evidenced environment/deployment problem:** this repository is being run as a bare Windows process (`E:\MBS\.venv`, `C:\Users\baran\...`, `next dev` on `localhost:3000` — see `uvicorn.log`, `web.log`, `celery_test_output.txt`), not inside the Docker Compose stack the code is built for. `.env`'s `DATABASE_URL` and the default `redis_url` (`redis://redis:6379/0`, `apps/api/core/config.py:158`) use **Docker-internal hostnames** (`mysql`, `redis`, `ollama`). `uvicorn.log` contains a **captured, real traceback**: `kombu.exceptions.OperationalError: Error 11001 connecting to redis:6379. getaddrinfo failed`, raised from `apps/api/modules/scans/service.py:112` — i.e., a scan-creation request that failed to dispatch its Celery task because the Windows process could not resolve the `redis` hostname. All eleven non-Katana external binaries (`nmap`, `nuclei`, `naabu`, `subfinder`, `httpx-pd`, `dnsx`, `whatweb`, `ffuf`, `amass`) plus the pip-installed `arjun` are only ever installed in `infra/docker/Dockerfile.worker` — they are Linux binaries baked into the worker container image, not into the developer's Windows PATH. Katana is a single, dependency-free Go binary and is the easiest of the eleven to install manually outside Docker, which is consistent with it being the one tool that "just works" while the rest silently fail at `asyncio.create_subprocess_exec(...)` with an OS-level "binary not found" error — an error the orchestrator **does catch and log correctly** (`tool.failed`, `ToolRun.status='failed'`, `error_message` populated), but which is easy to miss unless you inspect the per-tool `ToolRun` rows/pipeline widget rather than the polished report.

**Bottom line:** this is a well-engineered pipeline with no code-level silent-failure bug in the core execution/storage path I could find. The two real problems are (1) a UI omission that hides 4 of 12 tools' results, and (2) — the leading, evidence-backed but not 100%-runtime-confirmed explanation for "Katana works, the rest don't" — a **local dev environment that is not the container the tools were installed into**, compounded by a **broker-hostname mismatch that can silently strand whole scans in `queued` with zero tools ever executed.**

---

## B. Tool-by-Tool Results

| Tool | Execution | Output | Parsing | Storage | UI | Final Status |
|---|---|---|---|---|---|---|
| **subfinder** | UNKNOWN — INSUFFICIENT EVIDENCE (binary presence in the actual runtime not directly checkable from here) | Correct JSON-per-line parsing coded | `parse()` implemented correctly | Assets only (never vulnerabilities) | Shown (in `PHASE_ORDER`) | WORKING (recon) — asset-only tool |
| **amass** | UNKNOWN | Plain-text parsing coded | `parse()` correct | Assets only | **NOT shown** — missing from `ScanProgress.tsx` PHASE_ORDER/STAGES | UI FAILURE (results, if any, invisible in pipeline widget) |
| **dnsx** | UNKNOWN | JSON parsing coded | `parse()` correct | Assets only | **NOT shown** — same omission | UI FAILURE |
| **httpx** | UNKNOWN | JSON parsing coded | `parse()` correct | Assets only | Shown | WORKING (recon) — asset-only tool |
| **whatweb** | UNKNOWN | `--log-json=-` parsing coded | `parse()` correct | Assets only | **NOT shown** — same omission | UI FAILURE |
| **naabu** | UNKNOWN | JSON parsing coded | `parse()` correct | Assets only | Shown | WORKING (recon) — asset-only tool |
| **nmap** | UNKNOWN | `-oX -` XML parsing coded (`ET.fromstring`) | `parse()` correct | Assets only | Shown | WORKING (recon) — asset-only tool |
| **katana** | Confirmed capable of running standalone (user-observed) | Line-per-URL parsing coded | `parse()` correct | Assets only (URLs) — **never a vulnerability**, by design | Shown | WORKING (recon) — asset-only tool; **cannot** be the source of the "vulnerability report" content |
| **ffuf** | UNKNOWN; additionally **CONFIGURATION FAILURE if `FFUF_WORDLIST_PATH` isn't set in the actual runtime** (see §D/§F) | JSON-per-line parsing coded | `parse()` correct | Assets only | **NOT shown** — same omission | CONFIGURATION FAILURE risk + UI FAILURE |
| **arjun** | UNKNOWN; depends on `arjun` being both `pip install`ed (for wordlist resolution) *and* on PATH as a CLI (for the actual subprocess) | Own `-oJ` file + JSON parsing coded | `parse()` correct | Assets only (parameterised URLs) | Shown | WORKING (recon) if installed; asset-only regardless |
| **nuclei** | UNKNOWN; needs `-templates <dir>` (`NUCLEI_TEMPLATES_DIR`, baked into the Docker image only) | JSONL parsing coded | `parse_vulnerabilities()` implemented — **only tool besides nuclei-dast that can produce a Vulnerability row** | Vulnerabilities + Evidence + Risk + Compliance + ATT&CK mapping | Shown | The **only** other real candidate for "vulnerability report" content |
| **nuclei-dast** | Same binary/template dependency as nuclei, plus needs Katana/arjun output to have real fuzz targets | JSONL parsing coded (reuses nuclei's parser) | `parse_vulnerabilities()` — this is almost certainly the actual source of the "Command Injection — Generic Detection" / "SQL Injection" findings in the PDF you attached | Vulnerabilities + Evidence + Risk + Compliance + ATT&CK mapping | Shown | The other real candidate for the report content |

"UNKNOWN — INSUFFICIENT EVIDENCE" is used deliberately: I can read every runner's source and the Docker install steps, but I have no way, from a static read-only pass over the repository, to confirm which binaries are actually present on the PATH of whatever process is currently executing `run_scan_task` on your machine. That requires a runtime check (see §E/§L below).

---

## C. Katana Success Path (traced to code)

```
Target (domain/ip_range)
 ↓
scanner_engine/tool_registry.py — KatanaRunner registered, phase=45
 ↓
orchestrator.run_scan() → runners sorted by phase → _run_single_tool()
 ↓
KatanaRunner.run() (tool_runners/katana_runner.py:30)
    command = ["katana","-silent","-no-color","-depth",...,"-js-crawl","-jsluice",
               "-field-scope","fqdn","-concurrency","10","-rate-limit",...,"-timeout","10"]
    asyncio.create_subprocess_exec(*command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdin fed with newline-joined web_targets() (httpx-confirmed URL, else naabu/nmap port, else bare host)
 ↓
stdout captured (raw.stdout), stderr captured (raw.stderr), exit_code recorded
 ↓
orchestrator._run_single_tool():
    - evidence_store.store_raw_output() → raw stdout/stderr blob → S3/MinIO, sha256 checksum
    - Evidence row inserted (evidence_store.py, scanner_engine/models.py)
    - runner.parse(raw) → one CommonFinding(asset_type="url", ...) per discovered URL (capped at 500)
    - classify_run() → status "completed"/"partial"/"failed" from exit_code + whether output was usable
 ↓
upsert_asset() (modules/assets/service.py) → MySQL "assets" table, upserted on (target_id, asset_type, value)
 ↓
findings returned upward, accumulated into `discovered`, fed forward as prior_findings
    to later-phase tools (ffuf/arjun/nuclei/nuclei-dast use katana's URLs as fuzz targets
    via tool_runners/_web.py: crawled_urls())
 ↓
API: GET .../scans/{id}/tool-runs and GET .../assets serve these rows directly
 ↓
Frontend: ScanProgress.tsx renders "katana" (it IS in PHASE_ORDER/STAGES) — a completed row
    with duration; VulnerabilitiesTab.tsx would show NOTHING from katana (it never produces
    a Vulnerability row — parse_vulnerabilities() is not overridden, defaults to [])
```

Katana's pipeline works end-to-end for **assets**, and there is nothing katana-specific about why it would succeed where the vulnerability-producing tools (nuclei/nuclei-dast) fail — the code paths are structurally identical (`_run_single_tool` is the single shared entry point for every tool, with the same evidence-storage, parse, classify, and DB-write logic). The difference, if there is one, is external to this shared code: which binaries are actually reachable, and whether their runtime dependencies (nuclei's template directory, ffuf's wordlist path) are present.

---

## D. Other Tools' Paths — Where Data Could Disappear

```
Target
 ↓
Scanner (nuclei / nmap / ffuf / etc.)
 ↓
asyncio.create_subprocess_exec(name, ...)   ← FIRST POSSIBLE FAILURE POINT
    If `name` (e.g. "nuclei", "nmap", "ffuf", "amass", "whatweb", "arjun") is not on PATH
    in the process actually executing the Celery task, Python raises FileNotFoundError /
    OSError HERE, before any output exists.
 ↓
orchestrator._run_single_tool() except Exception as exc:      (orchestrator.py ~1128-1140)
    tool_run.status = "failed"
    tool_run.error_message = f"{type(exc).__name__}: {exc}"[:2000]
    record_tool_failure(runner.name)
    logger.error("tool.failed ...", exc_info=True)
    return [], "failed"
 ↓
This IS correctly recorded — NOT a silent failure in the code. It surfaces as:
    - a ToolRun row with status="failed" and a real error_message
    - a structured "tool.failed" log line
    - a per-stage red ✕ + error text in ScanProgress.tsx IF the tool is in PHASE_ORDER
      (amass/dnsx/whatweb/ffuf are NOT, so their failure is invisible there too)
 ↓
Zero assets/vulnerabilities are produced for that tool (correctly — findings/vuln_findings
    are set to [] on a "failed" classification, so nothing false is stored)
 ↓
Final UI: Vulnerabilities tab shows nothing from that tool (correct, if it genuinely
    didn't run) — but is INDISTINGUISHABLE, from the report alone, from "it ran and found
    nothing." You have to open Tool Runs / the pipeline widget to tell the two apart, and
    for 4 of the 12 tools the pipeline widget won't show them even then.
```

A second, independent failure mode exists **before** any tool runs at all:

```
POST /scans (create_scan, modules/scans/service.py:110-137)
 ↓
Scan row committed: status="queued"                    ← durable
 ↓
run_scan_task.delay(...)                                ← THIS is where the captured
    kombu.exceptions.OperationalError: Error 11001 connecting to redis:6379.
    getaddrinfo failed   (see uvicorn.log, matches service.py:112 exactly)
 ↓
If this raises and is NOT swallowed by the caller, the API request 500s, but the
    Scan row is ALREADY committed as "queued" with celery_task_id=NULL.
 ↓
That scan now depends entirely on the beat-scheduled `_relay_queued()` sweep
    (celery_app/tasks/scan_tasks.py:254) to ever be dispatched — which itself requires
    Celery beat to be running AND Redis to be reachable by then. If neither holds in
    your local setup, the scan sits in "queued" forever: NO tool — not even katana —
    ever executes for it.
```

This second mode does not, by itself, explain "katana succeeds, others fail" (a fully-stranded scan runs nothing at all). But it is directly proven by your own logs to be an active failure mode in this environment, and it means: **some of what looks like "no report" may not be a tool problem at all — it may be scans that never left the queue.**

---

## E. Root Causes

### Confirmed problems (directly proven by the code)

1. **`ScanProgress.tsx` (apps/web/components/project/ScanProgress.tsx:10-21)** — the `STAGES` and `PHASE_ORDER` constants list only `subfinder, httpx, naabu, nmap, katana, arjun, nuclei, nuclei-dast`. **`amass`, `dnsx`, `whatweb`, and `ffuf` are absent.** `stages = PHASE_ORDER.filter(m => requested.includes(m))` (line 78) means any `ToolRun` for those 4 tools is fetched (line 66, `scanApi.toolRuns`) but never iterated into a `<StageRow>` — its status, findings, and even its *failure* are invisible in this widget, regardless of whether the tool ran, partially ran, or hard-failed. This is a genuine "results stored but not displayed" bug (§5 State 7) for exactly those 4 tools.
2. **Every non-nuclei/nuclei-dast tool structurally cannot produce a `Vulnerability` row.** `BaseToolRunner.parse_vulnerabilities()` (`tool_runners/base.py:112-116`) defaults to `return []` and is overridden only in `nuclei_runner.py:81`. `NucleiDastRunner` inherits it unchanged (`nuclei_dast_runner.py` has no override). This is by design per the code's own docstrings ("Nuclei produces vulnerabilities, not inventory assets" — `nuclei_runner.py:78`), not a bug — but it means the Executive/Technical report (`modules/reports/data.py`, built purely from the `vulnerabilities` table) can *only ever* reflect nuclei/nuclei-dast output. Nothing else you run will ever appear there, however well it ran.
3. **`.env`/`config.py` default hostnames are Docker-internal**, and the developer-facing artifacts in this checkout (`uvicorn.log`, `web.log`, `celery_test_output.txt`, `.venv` under `E:\MBS`) show the app running as native Windows processes, not inside `docker-compose`. `uvicorn.log` contains a captured real failure: `run_scan_task.delay()` → `kombu.exceptions.OperationalError: Error 11001 connecting to redis:6379` at `modules/scans/service.py:112`.
4. **`infra/docker/Dockerfile.worker`** is the only place in the repository that installs `nmap`, `naabu`, `subfinder`, `httpx` (as `httpx-pd`), `nuclei` (+ its ~19 MB template bundle), `dnsx`, `whatweb`, `katana`, `amass`, `ffuf`, and `arjun`. All are installed as Linux binaries/packages into `/usr/local/bin` or the container's Python environment. There is no evidence anywhere in the repo of a Windows-native install path for any of these tools.
5. **`ffuf_runner.py:37-41`** hard-fails (`exit_code=-1`, `"no wordlist configured"`) if neither `config["ffuf_wordlist_path"]` nor `settings.ffuf_wordlist_path` is set. The only place that value is ever set is `ENV FFUF_WORDLIST_PATH=/usr/share/dirb/wordlists/common.txt` inside `Dockerfile.worker` — a path that only exists inside that container.
6. **`nuclei_runner.py:48-50`** only passes `-templates <dir>` if `get_settings().nuclei_templates_dir` is non-empty; the default in `config.py:270` is `""`. The only place `NUCLEI_TEMPLATES_DIR` is set is `Dockerfile.worker`'s `ENV NUCLEI_TEMPLATES_DIR=/home/appuser/nuclei-templates`, populated by a build-time download of the nuclei-templates repo baked into that image. Outside that container, nuclei either can't find templates (if you happen to have the `nuclei` binary on PATH but no `-templates` flag, it falls back to nuclei's own ambient template search, which usually means "0 templates loaded" on a machine that never ran `nuclei -update-templates`) or the `nuclei` binary itself is simply absent.

### Probable problems (strongly suggested, need runtime confirmation)

7. **Only Katana is actually on the executing process's PATH.** This is the most likely single explanation for "Katana works, the rest silently don't." Reasoning: Katana is the one tool in the list with zero external runtime dependency (no template directory, no wordlist file, no interpreter beyond the static binary itself), making it by far the easiest of the eleven external tools to hand-install on a bare Windows dev box — everything else needs either a Linux/WSL environment, a matching Windows release + manual PATH setup, an interpreter (Ruby for `whatweb`), or a populated data directory (`nuclei`, `ffuf`). If this is correct, every other tool's `ToolRun.run()` call raises `FileNotFoundError`/`OSError` at the `asyncio.create_subprocess_exec()` call site, correctly caught and recorded as `status="failed"` by `_run_single_tool`'s exception handler — meaning the platform's own audit trail (the `tool_runs` table, and the `error_message` column specifically) should already contain the exact confirmation of this (or refute it) if queried.
8. **Some scans may have never been dispatched at all** (§D, second diagram) if the Redis-hostname failure captured in `uvicorn.log` recurred for scan-creation requests and the beat-scheduled relay (`_relay_queued`) either never ran locally (Celery beat is a separate process most local dev setups skip) or also couldn't reach Redis.
9. **`nmap`/`naabu` may require elevated privileges or a firewall exception on Windows** that they don't need inside the Linux container (the code deliberately uses `-sT`/`-scan-type connect` to avoid needing raw sockets, but Windows Defender Firewall / npcap driver requirements for `nmap.exe` specifically are a well-known local friction point outside this codebase's control).

### Possible problems (cannot be proven from static analysis — need the runtime evidence in §L)

10. Whether `arjun` is installed as a *CLI* (not just importable as a Python module) in whatever environment executes scans.
11. Whether the object-storage backend (`evidence_store.py`, MinIO/S3) is reachable from the same environment — a storage outage is fail-soft (downgrades `completed`→`partial`, §F below) so it wouldn't zero out findings, but it would degrade every tool's status uniformly, not explain a katana-vs-others split.
12. Whether the executive-report PDF you attached was generated from *this* environment at all, or from a different (e.g. staging/production Docker) deployment where nuclei/nuclei-dast genuinely did run — the PDF's `Generated: 2026-08-25 18:07 UTC` timestamp and "Project: linc" name don't obviously correlate to the `celery_test_output.txt`/`uvicorn.log` timestamps in this checkout, and I have no way to confirm the origin from static files alone.

---

## F. Evidence (file / function / behavior / why it matters)

- **`apps/api/scanner_engine/tool_runners/base.py:112-116`** — `parse_vulnerabilities()` default returns `[]`; only `nuclei_runner.py:81-125` overrides it non-trivially. **Why it matters:** structurally proves only nuclei/nuclei-dast can ever produce a `Vulnerability` row — every other tool's output is asset-only by construction, not by failure.
- **`apps/api/scanner_engine/orchestrator.py:1052-1273` (`_run_single_tool`)** — single shared code path for every tool: subprocess exception → `status="failed"`, `error_message` set, `record_tool_failure`, structured log, `return [], "failed"` (lines ~1128-1140); parse exceptions are caught separately and degrade to empty findings rather than crashing the tool run (lines ~1163-1172); evidence-storage failures downgrade `completed`→`partial` rather than losing the run silently (lines ~1105-1119, ~1156-1158). **Why it matters:** rules out Possibility B/C/D/H for the reviewed core path — there is no code-level silent swallow here; a failure is always visible in the `tool_runs` table if you look.
- **`apps/api/modules/reports/data.py:22-51` (`ReportData`/`VulnRow`) and `render.py:34-88` (`render_executive`)** — report content is built entirely from `Vulnerability` rows via `data.vulns`; there is no code path that pulls `Asset` rows (Katana/subfinder/httpx/etc.'s output) into this report. **Why it matters:** proves the Executive Report cannot, under any circumstance, contain Katana output — anything attributed to Katana "in the report" must actually be a misreading of the Assets tab or the scan pipeline widget, not the Executive/Technical report itself.
- **`apps/web/components/project/ScanProgress.tsx:10-21`** — `STAGES`/`PHASE_ORDER` list 8 of the 12 registered tools; `amass`, `dnsx`, `whatweb`, `ffuf` are absent. Line 78: `const stages = PHASE_ORDER.filter((m) => requested.includes(m));`. **Why it matters:** this is a concrete, provable UI bug — those 4 tools' `ToolRun` rows (fetched at line 66) are silently dropped from the rendered stage list, independent of whether they succeeded, partially succeeded, or failed.
- **`E:\MBS\.env:29`** — `DATABASE_URL=mysql+aiomysql://mbs:mbs@mysql:3306/mbs` (Docker Compose hostname `mysql`); **`.env:50`** — `# REDIS_URL=redis://127.0.0.1:6379/0` is commented out, so the code default applies. **`apps/api/core/config.py:158`** — `redis_url: str = "redis://redis:6379/0"` (Docker Compose hostname `redis`). **Why it matters:** the active configuration in this checkout points every infra dependency at Docker-internal DNS names.
- **`E:\MBS\uvicorn.log`** — a captured real traceback: `File "E:\MBS\apps\api\modules\scans\service.py", line 112, in create_scan / async_result = run_scan_task.delay(...) / ... / kombu.exceptions.OperationalError: Error 11001 connecting to redis:6379. getaddrinfo failed.` **Why it matters:** this is not a hypothesis — it is a real, logged failure of scan dispatch in this exact codebase/checkout, proving the Docker-hostname/local-runtime mismatch actively broke at least one scan-creation attempt.
- **`E:\MBS\celery_test_output.txt`** — pytest failures reference `E:\MBS\.venv\Lib\site-packages\...` and `C:\Users\baran\AppData\Local\Temp\pytest-of-baran\...`. **Why it matters:** confirms the test/dev process runs as a native Windows Python process, not inside the Linux `Dockerfile.worker` image where the 11 non-Katana tools are installed.
- **`infra/docker/Dockerfile.worker:1-234`** — the sole installation site for `nmap` (apt), `naabu`/`subfinder`/`httpx`(as `httpx-pd`)/`nuclei`/`dnsx` (GitHub release zips, Linux amd64), `whatweb`/`dirb` (apt), `katana`/`amass`/`ffuf` (GitHub release archives, Linux), `arjun` (`pip install arjun==2.2.7`), plus `NUCLEI_TEMPLATES_DIR` and `FFUF_WORDLIST_PATH` environment variables and the baked-in nuclei-templates archive. **Why it matters:** establishes that the intended, tested execution environment for every tool except possibly a manually-installed Katana is this container image — nothing in the repo provides a Windows-native equivalent.
- **`apps/api/scanner_engine/tool_runners/ffuf_runner.py:37-41`** — `if not wordlist: return RawToolOutput(..., stderr="no wordlist configured", exit_code=-1)`. **Why it matters:** a concrete, named configuration-failure mode outside Docker, distinct from "binary missing."
- **`apps/api/scanner_engine/doctor.py`** — a real-execution self-test module (`python -m apps.api.scanner_engine.doctor`) that runs every recon tool (not ffuf/arjun/katana/nuclei-dast/amass/whatweb/dnsx — it covers 8 of 12) against `scanme.nmap.org` and reports PASS/FAIL per tool. **Why it matters:** this is the tool the codebase itself provides to answer exactly the question you're asking — see §L below.

---

## G. Improvements — Recommendations Only (nothing implemented)

### Priority 1 — Critical
- Fix `apps/web/components/project/ScanProgress.tsx`'s `STAGES`/`PHASE_ORDER` to include `amass`, `dnsx`, `whatweb`, `ffuf` (or, better, derive the stage list from `TOOL_REGISTRY`'s `phase` ordering via an API-exposed capability list, so the frontend can never drift out of sync with the backend's registered tools again — this exact class of bug will recur every time a tool is added, as it apparently already has).
- Resolve the Docker-hostname-vs-local-runtime mismatch: either run the full stack via `docker compose up` (including the worker image where all 11 non-Katana binaries live), or, for local Windows development, point `DATABASE_URL`/`REDIS_URL` at `127.0.0.1`-mapped ports (the `.env` file already has the correct commented-out lines for this — they're just not active) and separately install/validate every scanner binary (or accept that only Docker-executed scans are meaningful for QA).
- Run `python -m apps.api.scanner_engine.doctor` **inside the actual environment that executes your Celery worker** (see §L) — this is the single fastest, code-provided way to convert every "UNKNOWN — INSUFFICIENT EVIDENCE" row in §B into a definitive PASS/FAIL per tool.

### Priority 2 — High
- Add an explicit, visible distinction in the UI between "tool ran, found nothing" and "tool never executed / failed to launch" — today this exists in the data (`ToolRun.status` + `error_message`) but requires opening the pipeline widget or tool-run detail; it is not surfaced anywhere in the Vulnerabilities tab or the Executive Report, so a report reader has no way to tell "clean" from "untested."
- Extend `scanner_engine/doctor.py` to cover `ffuf`, `arjun`, `katana`, `nuclei-dast`, `amass`, `whatweb`, and `dnsx` (currently 8 of 12 tools are covered) so the self-test is a complete toolchain health check, not a partial one.
- Consider a startup/health-check log line (or `/health` endpoint field) that reports, once, which of the 12 tool binaries are actually resolvable on PATH in the current worker process — this would have made "why does only Katana work" a one-line answer instead of a forensic investigation.

### Priority 3 — Medium
- The report generator (`modules/reports/data.py`) could optionally surface a small "Recon coverage" section (asset counts per tool, tool run success/failure summary) alongside the vulnerability-only content, so a reader isn't left assuming "no vulnerabilities" and "no data" are the same thing.
- `_relay_queued()`'s dependency on Celery beat running is a single point of failure for recovering scans whose initial dispatch failed (as captured in `uvicorn.log`); consider alerting (not just logging) when a scan sits `queued` with `celery_task_id IS NULL` past a shorter threshold.

### Priority 4 — Nice to Have
- Surface `tool_run.command` (already stored, e.g. via `command_hash`/evidence blob) directly in the Tool Run detail UI for easier manual reproduction/debugging of exactly what was executed.
- A small CLI/admin command to print `TOOL_REGISTRY` alongside `PHASE_ORDER`-style frontend constants at CI time, failing the build if they diverge, would prevent the exact drift found in §B.4.

---

## H. What I could NOT confirm from static analysis

Per your instruction not to fabricate: the following require runtime evidence I do not have from a read-only pass over the repository, and I have not claimed otherwise anywhere above:

- Whether `nuclei`, `nmap`, `naabu`, `subfinder`, `httpx-pd`, `dnsx`, `whatweb`, `ffuf`, `amass`, and `arjun` are actually present/absent on the PATH of the process that runs `celery -A apps.api.celery_app.worker.celery_app worker` in your environment right now.
- The actual current contents of the `tool_runs` table (status/error_message per tool per recent scan) — this would immediately confirm or refute the "only Katana's binary is present" hypothesis.
- Whether the attached PDF was generated by this checkout/environment or a different one.
- Whether Redis/MySQL/MinIO are reachable right now from wherever the Celery worker actually runs.

---

## L. The fastest way to get a definitive answer

The codebase already ships the exact tool for this: `apps/api/scanner_engine/doctor.py`. Run, **from inside whatever process/environment actually executes your scans** (the Celery worker's own venv/container, not necessarily this checkout's `.venv`):

```
python -m apps.api.scanner_engine.doctor
```

It runs subfinder, amass, dnsx, httpx, whatweb, naabu, nmap, and nuclei against the Nmap project's own sanctioned test target (`scanme.nmap.org`) and prints a PASS/FAIL line with the real exit code, asset/vuln counts, and a stderr tail for each — exactly the "did it actually run" evidence this whole investigation is trying to establish, but authoritative and in under a minute. (It does not cover `ffuf`, `arjun`, `katana`, `nuclei-dast`; those would need the same real-execution treatment separately, or extending `doctor.py` per the Priority 2 recommendation above.)

---

## M. Final Answer to Your Closing Question

> *Is the current system actually receiving results from all security tools and simply not displaying them, or are the other tools failing/not producing results, while Katana is the only tool whose complete output pipeline currently works?*

Based strictly on the code: **it is not one single answer, it is two independent things layered on top of each other.**

First, structurally and by design, "vulnerability report" content can only ever come from `nuclei`/`nuclei-dast` — Katana and every other recon tool feed the pipeline (Katana specifically feeds nuclei-dast's fuzz targets) but can never themselves produce a vulnerability finding, so comparing Katana's presence in a vulnerability report against other tools' absence is comparing tools that were never capable of the same output in the first place. That part is Possibility A/§14, not a defect.

Second, and this is the part that actually explains an operational "Katana works, nothing else does": the evidence in this checkout (`.env`'s Docker-internal hostnames, `uvicorn.log`'s captured Redis-connection failure at the exact line that dispatches scan tasks, and `Dockerfile.worker` being the sole installation site for all eleven non-Katana binaries) points strongly — though not with 100% runtime certainty from static analysis alone — to this being executed in a local Windows environment that was never given the other ten tool binaries, while Katana (the one dependency-free static binary among them) was. The orchestrator's own execution/storage code is not silently swallowing anything here; a missing binary produces a correctly-recorded `ToolRun.status="failed"` row with a real error message — it just isn't surfaced anywhere prominent (and for `amass`/`dnsx`/`whatweb`/`ffuf` specifically, a confirmed frontend bug means even a *successful* run of those four would never show in the scan pipeline widget). Running `python -m apps.api.scanner_engine.doctor` inside the actual worker environment, or querying the `tool_runs` table's `status`/`error_message` columns for a recent scan, will convert this from "most likely explanation" to a confirmed fact in minutes.
