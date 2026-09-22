# Test Coverage & CI Gate (Phase 1.7)

CI enforces a **minimum total test-coverage threshold**. If coverage drops below it, the
`tests` job fails.

## Threshold
- **Default: 80%** (branch coverage enabled).
- Configured in [`pyproject.toml`](../pyproject.toml) → `[tool.coverage.report] fail_under = 80`.
- CI reads `COVERAGE_FAIL_UNDER` (default `80`) and passes `--cov-fail-under`, so a run can
  be overridden without editing config. **Lower the threshold only intentionally.**

## Run coverage locally
From the repo root (or inside the API container, `cd /srv`):

```bash
python -m pytest apps/api/tests \
  --cov=apps/api \
  --cov-report=term-missing \
  --cov-report=html \
  --cov-report=xml \
  --cov-fail-under=80
```

Notes:
- Requires a running MySQL + Redis (the suite uses a real DB for tenancy tests). The dev
  containers already provide these; from the host, point `DATABASE_URL`/`REDIS_URL` at them.
- Plain `pytest apps/api/tests -q` still works and is **not** slowed by coverage — the
  `--cov` flags are opt-in per run (coverage is not forced in `addopts`).
- In the dockerised dev environment: `docker exec infra-api-1 sh -c 'cd /srv && python -m
  pytest apps/api/tests --cov=apps/api --cov-report=term-missing'`.

## View the HTML report
`--cov-report=html` writes `htmlcov/`. Open `htmlcov/index.html` in a browser to drill into
per-file, per-line coverage (red = uncovered). `coverage.xml` (Cobertura) is for CI tools.

## Change the threshold
1. Edit `fail_under` in `pyproject.toml` (the source of truth), **or**
2. Override for one CI run via the `COVERAGE_FAIL_UNDER` env in `.github/workflows/ci.yml`.

Raising it is a ratchet: bump it as coverage improves so it can't regress.

## What's measured
`[tool.coverage.run]` in `pyproject.toml`: `source = apps/api`, `branch = true`. Omitted:
the tests themselves, thin CLI shims (`apps/api/dr/__main__.py`, `apps/api/dr/cli.py`), and
`__init__.py` files. `[tool.coverage.report] exclude_lines` drops unreachable lines
(`if __name__ == "__main__"`, `TYPE_CHECKING`, `@abstractmethod`, `pragma: no cover`).

## CI behavior
The `tests` job (`.github/workflows/ci.yml`):
1. Spins up MySQL + Redis services, installs deps, applies migrations.
2. Runs `pytest apps/api/tests` with `--cov` + `--cov-fail-under=${COVERAGE_FAIL_UNDER}`.
3. **Fails the build if total coverage < threshold.**
4. Uploads `coverage.xml` + `htmlcov/` as the **`coverage`** artifact (`if: always()`, so the
   report is available even when the gate fails — download it from the run's Artifacts).
