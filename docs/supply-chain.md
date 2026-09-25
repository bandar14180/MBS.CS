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
  are reported-only, and each gate has an allowlist.
- **Both images gate (F-03).** `image-scan` (api) and `image-scan-worker` block on
  CRITICAL + fixed, honoring `.trivyignore`. The worker scan used to be
  `continue-on-error: true` *and* Trivy `exit-code: "0"` -- two neutralizers -- which left the
  2.35GB image that `worker`, `worker-default` and `beat` actually run completely ungated. See
  "Worker image gate" below.
- Reports (`pip-audit-report.json`, `sbom.cdx.json`, `trivy-api-report.json`, gitleaks
  report) are uploaded as artifacts even when a gate fails (`if: always()`), to aid triage.

## Scanner binary integrity (F-02)
The worker image installs eight security tools from GitHub **release archives**. Every one is
pinned twice — an exact version *and* a SHA-256 digest — and the digest is verified with
`sha256sum -c` **before** the archive is unpacked, inside `infra/docker/Dockerfile.worker`.
A mismatch exits non-zero and aborts the layer, so a tampered or truncated artifact can never
reach `/usr/local/bin`, let alone a customer scan.

| Tool | Version ARG | Digest ARG |
| --- | --- | --- |
| naabu | `NAABU_VERSION` | `NAABU_SHA256` |
| subfinder | `SUBFINDER_VERSION` | `SUBFINDER_SHA256` |
| httpx | `HTTPX_VERSION` | `HTTPX_SHA256` |
| nuclei | `NUCLEI_VERSION` | `NUCLEI_SHA256` |
| dnsx | `DNSX_VERSION` | `DNSX_SHA256` |
| katana | `KATANA_VERSION` | `KATANA_SHA256` |
| amass | `AMASS_VERSION` | `AMASS_SHA256` |
| ffuf | `FFUF_VERSION` | `FFUF_SHA256` |

**Why the digest is pinned in the Dockerfile rather than fetched at build time.** Downloading
`<tool>_checksums.txt` from the same release, over the same connection, proves only that the
archive matches whatever that host served — an attacker who can swap the binary can swap its
checksum file too. The trust anchor must live where the attacker does not control it, so it
lives in the reviewed, version-controlled tree: changing a digest is a visible diff.

**Bumping a tool version** — change the `*_VERSION` **and** its `*_SHA256` in the same commit:

```bash
VER=2.1.1
curl -sSfL "https://github.com/ffuf/ffuf/releases/download/v${VER}/ffuf_${VER}_checksums.txt"   | grep linux_amd64.tar.gz
```

Take the digest from the project's **official checksum asset for that exact tag**, and ideally
recompute it from the downloaded artifact as a cross-check (that is how the current values were
established — upstream checksum file *and* independent recomputation, agreeing for all eight).
A version bump without a matching digest bump fails the build loudly; that is intended.

Enforced by `apps/api/tests/test_supply_chain_config.py`: exact versions, 64-hex digests,
verification-before-unpack ordering, matching download/verification counts, no `|| true`
escape hatch, and no floating `releases/latest` URLs.

**Not covered:** the `nuclei-templates` archive is a codeload tarball of a git tag rather than
a release asset, and GitHub does not guarantee byte-stable archives for those, so a pinned
digest would break on re-generation. It is version-pinned and integrity-checked structurally
(zip parse + template-count floor) but not by digest — tracked separately from F-02.

## Worker image gate (F-03)
The worker image is the one that matters most: it carries nmap, whatweb, dirb, mysql-client,
Chromium and eight Go scanner binaries, and it is what the `worker`, `worker-default` and
`beat` services run in production against customer infrastructure. It is now gated exactly
like the api image.

| | api image | worker image |
| --- | --- | --- |
| Blocks on | CRITICAL + fixed | CRITICAL + fixed |
| `--ignore-unfixed` | yes | yes |
| `.trivyignore` honored | yes | yes |
| HIGH | reported, not blocking | reported, not blocking |
| `continue-on-error` | no | no |

**Why CRITICAL and not HIGH for the worker.** The eight scanner binaries statically link their
entire Go dependency tree, so a single Go stdlib advisory appears eight times over. Blocking on
HIGH would wedge CI on issues no version bump can clear, which trains people to disable the
gate -- the exact failure this finding was about. HIGH is still collected and uploaded as
`trivy-worker-report.json`.

**Scan doctor is split.** `scan-doctor-preflight` runs `--preflight-only` under
`--network none` and **blocks** (deterministic: are the binaries on PATH with their
prerequisites?). `scan-doctor` runs the live pass against `scanme.nmap.org` and stays
non-blocking, because external egress is genuinely flaky. Network flakiness is no longer a
reason for anything security-relevant to be advisory.

**Local parity.** `scripts/supply_chain.sh image` now builds and scans **both** images with the
same policy CI uses. The worker build is large (~2.35GB, eight tool archives plus the nuclei
template set), so expect several minutes on a cold cache; the script builds it itself and a
build failure fails the gate rather than skipping the scan.

**Accepted exceptions.** `.trivyignore` carries four CVEs, each with package, affected layer,
why it is unfixable today, why it is not reachable in this image, a remediation plan and a
review date. They are all upstream-vendored Go modules that no current tool release has
rebuilt against. Blanket or category-wide suppression is not permitted and is rejected by
`test_trivyignore_entries_are_individually_justified`.

## Deployment / environment notes
The scanners require network (advisory DBs, image builds, Trivy DB) and run in GitHub
Actions. In a network-restricted local environment (e.g. behind a TLS-intercepting proxy)
the actual scans may not run; the config, SBOM generation, and gate wiring are still
validated by `apps/api/tests/test_supply_chain_config.py`.
