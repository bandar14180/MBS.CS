"""AUDIT-007 -- documentation must describe the tenancy mechanism that actually exists.

THE PROBLEM
-----------
The Phase 0 cutover moved this system from PostgreSQL 16 to MySQL 8. MySQL has no row-level
security, so tenant isolation moved from database policies (`ENABLE`/`FORCE ROW LEVEL
SECURITY`, keyed on `current_setting('app.current_workspace_id')`) to an application-layer ORM
filter in `apps/api/core/tenancy.py`. The mechanism changed completely; a large amount of prose
did not.

Docstrings claiming a table is "FORCE-RLS on workspace_id" or that a function "runs with the
workspace GUC already set" are not cosmetic drift. They tell the next engineer that the
database will catch a mistake, when in fact nothing will:

  * raw SQL bypasses the ORM filter entirely (hence the raw-SQL inventory + its CI gate), and
  * AGGREGATES escape `with_loader_criteria` too, so `select(func.count())` without an explicit
    workspace predicate returns a cross-tenant number.

Someone who believes the docstring writes exactly that query and ships a leak.

WHAT IS ENFORCED HERE
---------------------
Production code (apps/api, excluding tests) must not make a PRESENT-TENSE claim that RLS or a
workspace GUC is doing the scoping. Mentions that explain the history -- "this WAS RLS", "there
is NO RLS in MySQL", "the old Postgres design" -- are correct, valuable, and explicitly allowed:
the codebase should remember why it looks the way it does.

Deliberately NOT in scope:
  * `db/migrations/archived_postgres/**` -- an accurate archive of the Postgres era.
  * The dated build log in `docs/architecture/blueprint.md` -- a historical record. Rewriting
    those entries would falsify the project history, so the document carries a prominent
    cutover notice at the top instead, which this test requires.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
API_ROOT = REPO_ROOT / "apps" / "api"

# A claim that RLS / a GUC is presently doing the work.
CLAIM = re.compile(
    r"(FORCE[\s-]*RLS"
    r"|FORCE ROW LEVEL SECURITY"
    r"|ENABLE\s*\+\s*FORCE"
    r"|RLS[\s-]*(GUC|context|scoped|protected|exempt)"
    r"|(workspace|session)\s+RLS\b"
    r"|RLS\s+(policy|policies|session var|var)"
    r"|current_setting\("
    r"|workspace GUC"
    r"|RLS GUC)",
    re.I,
)

# Context that makes a mention historical/comparative rather than a present-tense claim.
HISTORICAL = re.compile(
    r"\b(was|were|used to|previously|formerly|pre-migration|no longer|historic|legacy|"
    r"removed|replaced|superseded|under the old|predates|prior to|cutover|archived|"
    r"stopped existing|there is no|has no|no native|does not exist|MDEV-27301|"
    r"originally|AUDIT-007|instead of|rather than|not\s+(a\s+)?(database|DB)\s+policy)\b",
    re.I,
)


def _iter_production_sources():
    if not API_ROOT.is_dir():
        pytest.skip("application tree not bind-mounted")
    for path in sorted(API_ROOT.rglob("*.py")):
        if {"tests", "__pycache__"} & set(path.parts):
            continue
        yield path


def test_production_code_makes_no_present_tense_rls_claim():
    """THE AUDIT-007 LOCK.

    Every remaining RLS/GUC mention in production code must be framed historically. A new
    docstring asserting that a table is "FORCE-RLS" fails here.
    """
    offenders: list[str] = []
    for path in _iter_production_sources():
        lines = path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines, 1):
            if not CLAIM.search(line):
                continue
            # Judge the claim in context: a sentence often spans several lines.
            context = " ".join(lines[max(0, n - 4):n + 3])
            if HISTORICAL.search(context):
                continue
            offenders.append(
                f"{path.relative_to(REPO_ROOT).as_posix()}:{n}: {line.strip()[:120]}"
            )
    assert not offenders, (
        "production code still claims PostgreSQL RLS / a workspace GUC enforces tenancy. "
        "MySQL has neither -- isolation is the ORM filter in apps/api/core/tenancy.py. "
        "Either describe the real mechanism, or frame the mention as history:\n"
        + "\n".join(offenders)
    )


def test_tenancy_module_documents_the_real_mechanism():
    """The module that IS the mechanism must say so plainly."""
    src = (API_ROOT / "core" / "tenancy.py").read_text(encoding="utf-8")
    lowered = src.lower()
    assert "contextvar" in lowered, "tenancy.py should document the contextvars-based binding"
    assert "mysql" in lowered, "tenancy.py should say which database it compensates for"
    # It must be explicit that RLS is NOT what is happening.
    assert re.search(r"no\s+(native\s+)?rls|rls.*mysql|mysql.*rls", lowered), (
        "tenancy.py should explain that MySQL has no RLS -- that is why this module exists"
    )


def test_blueprint_carries_the_cutover_notice():
    """The blueprint's dated build log legitimately still says "RLS enabled + forced". That is
    history and stays. But a reader must meet the correction BEFORE the history."""
    bp = REPO_ROOT / "docs" / "architecture" / "blueprint.md"
    if not bp.is_file():
        pytest.skip("blueprint not present")
    text = bp.read_text(encoding="utf-8")
    head = text[:6000]
    assert "AUDIT-007" in head and "tenancy.py" in head, (
        "docs/architecture/blueprint.md must carry a prominent cutover notice near the top "
        "explaining that its RLS statements describe the Postgres era, not the current system"
    )
    # The notice must appear BEFORE the first dated RLS build-log entry.
    notice_at = text.find("TENANCY MECHANISM CHANGED")
    assert notice_at != -1, "the cutover notice is missing"
    first_claim = CLAIM.search(text[notice_at + 3000:])
    if first_claim:
        assert notice_at < notice_at + 3000 + first_claim.start()


def test_readme_does_not_advertise_postgres_rls():
    """The README is the first thing anyone reads; it claimed Postgres FORCE RLS."""
    readme = REPO_ROOT / "README.md"
    if not readme.is_file():
        pytest.skip("README not present")
    text = readme.read_text(encoding="utf-8")
    for n, line in enumerate(text.splitlines(), 1):
        if CLAIM.search(line):
            context = line
            assert HISTORICAL.search(context), (
                f"README.md:{n} still advertises Postgres RLS as the isolation mechanism: "
                f"{line.strip()[:140]}"
            )


def test_archived_postgres_migrations_are_left_alone():
    """Guard against over-correction: the archive is an accurate record of the Postgres era and
    MUST keep its RLS statements. If this ever fails, someone 'cleaned up' real history."""
    archive = REPO_ROOT / "db" / "migrations" / "archived_postgres"
    if not archive.is_dir():
        pytest.skip("archived_postgres not present")
    joined = "\n".join(
        p.read_text(encoding="utf-8") for p in archive.rglob("*.py")
    )
    assert "ROW LEVEL SECURITY" in joined.upper(), (
        "the archived Postgres migrations no longer mention RLS -- historical accuracy was "
        "destroyed by an over-eager terminology sweep"
    )
