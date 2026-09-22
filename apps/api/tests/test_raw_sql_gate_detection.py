"""AUDIT-003 -- mutation tests for the raw-SQL scanner's DETECTION power.

test_supply_chain_config.py already asserts the gate is in sync with the inventory. That
proves the gate AGREES with the register; it does not prove the gate can SEE anything. The
AUDIT-003 finding was exactly that gap: the scanner matched only the bare callee names
`text` / `exec_driver_sql`, so three real production `cursor.execute(...)` sites sat in the
tree while the gate happily reported "OK -- 26 sites, all registered".

These tests are MUTATION tests. Each writes a synthetic module containing one raw-SQL
introduction pattern into a temporary tree, runs the real scanner over it, and asserts the
site is found. If someone narrows the detection again, the corresponding test fails.

The companion negative tests assert the exemptions still hold -- a gate that flags
`server_default=text(...)` or every `session.execute(select(...))` produces hundreds of false
positives, gets waived, and then protects nothing.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _inventory_module():
    """Import scripts/raw_sql_inventory.py by path (scripts/ is not a package)."""
    script = REPO_ROOT / "scripts" / "raw_sql_inventory.py"
    if not script.is_file():
        pytest.skip("scripts/raw_sql_inventory.py not present (repo root not bind-mounted)")
    spec = importlib.util.spec_from_file_location("raw_sql_inventory_mut", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scan_source(tmp_path: Path, source: str) -> list[dict]:
    """Run the real scanner over a throwaway tree containing exactly one module."""
    mod = _inventory_module()
    pkg = tmp_path / "apps" / "api"
    pkg.mkdir(parents=True)
    (pkg / "mutated.py").write_text(source, encoding="utf-8")
    return mod.scan(pkg)


def _mechanisms(sites: list[dict]) -> set[str]:
    return {s["mechanism"] for s in sites}


# --------------------------------------------------------------------------------------------
# POSITIVE: each introduction pattern the finding named must be detected.
# --------------------------------------------------------------------------------------------

def test_detects_plain_text_call(tmp_path):
    """Pattern #1 -- sqlalchemy.text(...) imported and called by its own name."""
    sites = _scan_source(tmp_path, (
        "from sqlalchemy import text\n"
        "def q(conn):\n"
        "    return conn.execute(text('SELECT * FROM vulnerabilities'))\n"
    ))
    assert "text" in _mechanisms(sites), f"plain text() not detected: {sites}"


def test_detects_module_qualified_text_call(tmp_path):
    """Pattern #2a -- reached through the module: sa.text(...)."""
    sites = _scan_source(tmp_path, (
        "import sqlalchemy as sa\n"
        "def q(conn):\n"
        "    return conn.execute(sa.text('SELECT * FROM scans'))\n"
    ))
    assert "text" in _mechanisms(sites), f"sa.text() not detected: {sites}"


def test_detects_aliased_text_import(tmp_path):
    """Pattern #2b -- THE AUDIT-003 CASE. `import text as <other>` must not hide the site."""
    sites = _scan_source(tmp_path, (
        "from sqlalchemy import text as sql_text\n"
        "def q(conn):\n"
        "    return conn.execute(sql_text('DELETE FROM audit_events'))\n"
    ))
    assert "text" in _mechanisms(sites), f"aliased text() not detected: {sites}"


def test_detects_exec_driver_sql(tmp_path):
    """Pattern #3 -- exec_driver_sql bypasses the SQL-compilation layer entirely."""
    sites = _scan_source(tmp_path, (
        "async def q(conn):\n"
        "    return await conn.exec_driver_sql('SELECT 1')\n"
    ))
    assert "exec_driver_sql" in _mechanisms(sites), f"exec_driver_sql not detected: {sites}"


def test_detects_aliased_exec_driver_sql(tmp_path):
    """Pattern #4 -- exec_driver_sql imported under an alias."""
    sites = _scan_source(tmp_path, (
        "from sqlalchemy import exec_driver_sql as eds\n"
        "def q():\n"
        "    return eds('SELECT * FROM workspaces')\n"
    ))
    assert "exec_driver_sql" in _mechanisms(sites), f"aliased exec_driver_sql not detected: {sites}"


def test_detects_dbapi_cursor_execute(tmp_path):
    """Pattern #5 -- raw DBAPI cursor.execute. Three of these were live in production and
    completely invisible to the pre-AUDIT-003 scanner."""
    sites = _scan_source(tmp_path, (
        "def q(conn):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute('SELECT * FROM users')\n"
    ))
    assert "cursor.execute" in _mechanisms(sites), f"cursor.execute not detected: {sites}"


def test_detects_dbapi_cursor_executemany(tmp_path):
    """Pattern #6 -- executemany is the same bypass, in bulk."""
    sites = _scan_source(tmp_path, (
        "def q(conn, rows):\n"
        "    cur = conn.cursor()\n"
        "    cur.executemany('INSERT INTO assets VALUES (%s)', rows)\n"
    ))
    assert "cursor.executemany" in _mechanisms(sites), f"cursor.executemany not detected: {sites}"


def test_detects_cursor_execute_via_unconventional_name(tmp_path):
    """The cursor receiver is resolved by ASSIGNMENT, not just by being named `cur` --
    renaming the variable must not hide the statement."""
    sites = _scan_source(tmp_path, (
        "def q(conn):\n"
        "    handle = conn.cursor()\n"
        "    handle.execute('SELECT * FROM projects')\n"
    ))
    assert "cursor.execute" in _mechanisms(sites), f"assignment-tracked cursor not detected: {sites}"


def test_detects_cursor_execute_in_with_block(tmp_path):
    """`with conn.cursor() as cur:` is the other common pymysql shape."""
    sites = _scan_source(tmp_path, (
        "def q(conn):\n"
        "    with conn.cursor() as c2:\n"
        "        c2.execute('SELECT * FROM reports')\n"
    ))
    assert "cursor.execute" in _mechanisms(sites), f"with-block cursor not detected: {sites}"


def test_detects_chained_cursor_execute(tmp_path):
    """`conn.cursor().execute(...)` -- no intermediate name to track."""
    sites = _scan_source(tmp_path, (
        "def q(conn):\n"
        "    conn.cursor().execute('SELECT * FROM targets')\n"
    ))
    assert "cursor.execute" in _mechanisms(sites), f"chained cursor.execute not detected: {sites}"


# --------------------------------------------------------------------------------------------
# NEGATIVE: the exemptions that keep the gate usable must survive.
# --------------------------------------------------------------------------------------------

def test_server_default_text_remains_exempt(tmp_path):
    """server_default=text(...) is DDL applied by the migration engine, not a runtime query.
    There are ~47 of these; flagging them would drown the real sites."""
    sites = _scan_source(tmp_path, (
        "from sqlalchemy import text\n"
        "from sqlalchemy.orm import mapped_column\n"
        "created_at = mapped_column(server_default=text('CURRENT_TIMESTAMP(6)'))\n"
    ))
    assert sites == [], f"schema default was wrongly flagged: {sites}"


def test_onupdate_and_default_text_remain_exempt(tmp_path):
    """The other two schema keywords carry the same exemption."""
    sites = _scan_source(tmp_path, (
        "from sqlalchemy import text\n"
        "from sqlalchemy.orm import mapped_column\n"
        "a = mapped_column(onupdate=text('CURRENT_TIMESTAMP(6)'))\n"
        "b = mapped_column(default=text('0'))\n"
    ))
    assert sites == [], f"onupdate/default were wrongly flagged: {sites}"


def test_orm_session_execute_is_not_flagged(tmp_path):
    """session.execute(select(...)) IS tenancy-filtered by apps/api/core/tenancy.py. Flagging
    every `.execute()` would make the gate meaningless noise."""
    sites = _scan_source(tmp_path, (
        "from sqlalchemy import select\n"
        "async def q(session, Model):\n"
        "    return await session.execute(select(Model))\n"
    ))
    assert sites == [], f"ORM session.execute was wrongly flagged: {sites}"


def test_unrelated_text_attribute_is_not_flagged(tmp_path):
    """`resp.text` / `path.read_text()` on a non-sqlalchemy object must not match -- the
    module alias map is what distinguishes them."""
    sites = _scan_source(tmp_path, (
        "import httpx\n"
        "def q(resp, path):\n"
        "    a = resp.text\n"
        "    return path.read_text()\n"
    ))
    assert sites == [], f"unrelated .text was wrongly flagged: {sites}"


def test_scanner_reports_line_and_file_for_each_site(tmp_path):
    """The gate's failure output must name the exact location, or it is not actionable."""
    sites = _scan_source(tmp_path, (
        "from sqlalchemy import text\n"
        "def q(conn):\n"
        "    return conn.execute(text('SELECT 1'))\n"
    ))
    assert len(sites) == 1
    assert sites[0]["line"] == 3
    assert sites[0]["file"].endswith("mutated.py")
    assert "SELECT 1" in sites[0]["snippet"]


# --------------------------------------------------------------------------------------------
# The real tree: the three sites AUDIT-003 exposed must now be registered, not merely findable.
# --------------------------------------------------------------------------------------------

def test_previously_missed_cursor_sites_are_now_in_the_inventory():
    """Regression lock for the concrete AUDIT-003 evidence: these production DBAPI cursor
    statements existed while the gate reported a clean 26/26."""
    mod = _inventory_module()
    if not (REPO_ROOT / "apps" / "api" / "dr" / "service.py").is_file():
        pytest.skip("application tree not bind-mounted")
    found = {(s["file"], s["mechanism"]) for s in mod.scan()}
    assert ("apps/api/core/observability.py", "cursor.execute") in found
    assert ("apps/api/dr/service.py", "cursor.execute") in found

    registered = mod.load_inventory()
    # MBS.SC: this probe moved 305 -> 416 when the scanner-isolation metrics were added
    # above it in observability.py, then 416 -> 558 when the verification/evidence metrics
    # (Prompt 33) were added above it in the same file. The line number is the inventory's
    # identifier by design (an edit or a move must surface as drift and be re-reviewed), so
    # the expected value is updated here rather than the assertion being loosened -- the
    # property under test is that the cursor site is REGISTERED, and it still is.
    assert 558 in registered.get("apps/api/core/observability.py", set())
    assert {506, 509} <= registered.get("apps/api/dr/service.py", set())
