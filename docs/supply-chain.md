# Supply Chain Security (Phase 1.8)

CI enforces backend supply-chain checks: a **gated** Python dependency audit, an **SBOM**,
a **container image scan**, and **secret scanning**. All are additive — no application,
API, DB, or schema changes. (Frontend `npm audit` and hash-pinned installs are
intentionally out of scope for this phase.)

## What runs in CI (`.github/workflows/ci.yml`)
| Job | Tool | Gates the build? | Notes |
| --- | --- | --- | --- |
| `supply-chain` | `pip-audit` + CycloneDX | **Yes** (audit) | Audits `apps/api/requirements.txt`; SBOM is generated as **JSON** (`python -m cyclonedx_py requirements … --of JSON`); uploads `pip-audit-report.json` + `sbom.cdx.json`. |
| `image-scan` | Trivy (api image) | **Yes** — CRITICAL, fixed only | `--ignore-unfixed` + `.trivyignore`; HIGH/CRITICAL report uploaded (non-gating). |
| `image-scan-worker` | Trivy (worker image) | No (informational) | Heavy/flaky build; reports HIGH/CRITICAL, never blocks. |
| `secret-scan` | gitleaks (pinned **CLI**) | **Yes** | Deterministic **filesystem** scan: `gitleaks detect --no-git --config .gitleaks.toml --exit-code 1`. Uses the pinned CLI (not `gitleaks-action`), so **no org-license** is required; identical semantics to `scripts/supply_chain.sh`. Report artifact uploaded. |

The pre-existing `tests` (coverage gate) and `scan-doctor` jobs are unchanged.

## Run locally
Security tooling is pinned in `apps/api/requirements-dev.txt` (separate from runtime deps):
```bash
pip install -r apps/api/requirements-dev.txt        # pip-audit + cyclonedx-py
# Trivy + gitleaks are separate binaries (install from their projects) for the image/secret checks.

scripts/supply_chain.sh            # run every check the local toolchain supports
scripts/supply_chain.sh audit      # dependency audit only
scripts/supply_chain.sh sbom       # write sbom.cdx.json
scripts/supply_chain.sh image      # build + Trivy scan the api image (docker + trivy)
scripts/supply_chain.sh secrets    # gitleaks filesystem scan
```
Each check self-skips (with a notice) if its tool is missing, so a partial toolchain still
runs what it can. The script mirrors the CI gates exactly.

## Updating the allowlists (triage workflow)
Each gate has one auditable allowlist file. Add an entry **only** with a justification and a
review-by date so the allowlist stays honest.

- **Dependency advisory** — `.security/pip-audit-ignore.txt`: one advisory ID per line
  (`PYSEC-…` / `GHSA-…`). CI passes each as `pip-audit --ignore-vuln <ID>`. Prefer fixing
  (pin/upgrade the dependency) over ignoring; ignore only when there's no fix or it's not
  reachable.
- **Container CVE** — `.trivyignore`: one CVE ID per line. Only needed for a rare
  CRITICAL-with-fix that's reviewed and accepted (the gate already skips unfixed CVEs).
- **Secret false positive** — `.gitleaks.toml` `[allowlist]`: add a tight `paths` or
  `regexes` entry (never a broad pattern that could mask a real leak). Dev defaults
  (`minioadmin`, `mbs:mbs@`), config placeholders, and test fixtures are pre-allowlisted.

## Reading the SBOM
`sbom.cdx.json` is a CycloneDX SBOM of the Python runtime dependencies, uploaded as the
`supply-chain` artifact on every run. Feed it to any CycloneDX-aware tool (dependency-track,
`cyclonedx` CLI) for inventory / license / vulnerability correlation.

## CI behavior summary
- A **new** dependency advisory, a **CRITICAL fixed** CVE in the api image, or a **real
  secret** fails CI.
- **Non-actionable** findings do not wedge CI: unfixed CVEs are ignored, HIGH image findings
  are reported-only, the worker image scan is informational, and each gate has an allowlist.
- Reports (`pip-audit-report.json`, `sbom.cdx.json`, `trivy-api-report.json`, gitleaks
  report) are uploaded as artifacts even when a gate fails (`if: always()`), to aid triage.

## Deployment / environment notes
The scanners require network (advisory DBs, image builds, Trivy DB) and run in GitHub
Actions. In a network-restricted local environment (e.g. behind a TLS-intercepting proxy)
the actual scans may not run; the config, SBOM generation, and gate wiring are still
validated by `apps/api/tests/test_supply_chain_config.py`.
