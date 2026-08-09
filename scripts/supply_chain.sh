#!/usr/bin/env bash
# Phase 1.8 -- run the supply-chain security checks locally (mirrors CI).
#
#   scripts/supply_chain.sh            # run all available checks
#   scripts/supply_chain.sh audit      # dependency audit only
#   scripts/supply_chain.sh sbom       # SBOM only
#   scripts/supply_chain.sh image      # container image scan (needs docker + trivy)
#   scripts/supply_chain.sh secrets    # secret scan (needs gitleaks)
#
# Tools: pip-audit + cyclonedx-py (pip install -r apps/api/requirements-dev.txt),
# trivy, and gitleaks. Each check is skipped with a notice if its tool is absent, so a
# partial local toolchain still runs what it can. Mirrors the CI gates in
# .github/workflows/ci.yml -- see docs/supply-chain.md.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REQ="$ROOT/apps/api/requirements.txt"
IGNORE_FILE="$ROOT/.security/pip-audit-ignore.txt"
rc=0

_have() { command -v "$1" >/dev/null 2>&1; }

_audit() {
  if ! _have pip-audit; then echo "[skip] pip-audit not installed (pip install -r apps/api/requirements-dev.txt)"; return 0; fi
  local args=""
  if [ -f "$IGNORE_FILE" ]; then
    while IFS= read -r line; do
      id="${line%%#*}"; id="$(echo "$id" | tr -d '[:space:]')"
      [ -n "$id" ] && args="$args --ignore-vuln $id"
    done < "$IGNORE_FILE"
  fi
  echo "[audit] pip-audit${args:+ (ignoring:$args)}"
  # shellcheck disable=SC2086
  pip-audit -r "$REQ" --strict --desc $args || rc=1
}

_sbom() {
  if ! _have cyclonedx-py; then echo "[skip] cyclonedx-py not installed"; return 0; fi
  echo "[sbom] -> sbom.cdx.json"
  cyclonedx-py requirements "$REQ" -o "$ROOT/sbom.cdx.json" || rc=1
}

_image() {
  if ! _have docker || ! _have trivy; then echo "[skip] image scan needs docker + trivy"; return 0; fi
  echo "[image] building + scanning api image (CRITICAL, fixed only)"
  docker build -f "$ROOT/infra/docker/Dockerfile.api" -t mbs-api:local "$ROOT" || { rc=1; return; }
  trivy image --severity CRITICAL --ignore-unfixed --ignorefile "$ROOT/.trivyignore" --exit-code 1 mbs-api:local || rc=1
}

_secrets() {
  if ! _have gitleaks; then echo "[skip] gitleaks not installed"; return 0; fi
  echo "[secrets] gitleaks filesystem scan (--no-git, gated) -- same semantics as CI"
  gitleaks detect \
    --source "$ROOT" \
    --no-git \
    --config "$ROOT/.gitleaks.toml" \
    --redact \
    --report-format json \
    --report-path "$ROOT/gitleaks-report.json" \
    --exit-code 1 || rc=1
}

case "${1:-all}" in
  audit)   _audit ;;
  sbom)    _sbom ;;
  image)   _image ;;
  secrets) _secrets ;;
  all)     _audit; _sbom; _image; _secrets ;;
  *) echo "usage: $0 [all|audit|sbom|image|secrets]"; exit 2 ;;
esac

[ "$rc" -eq 0 ] && echo "[supply-chain] OK" || echo "[supply-chain] FAILURES (rc=$rc)"
exit "$rc"
