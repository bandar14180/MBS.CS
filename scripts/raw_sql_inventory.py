#!/usr/bin/env python3
"""Raw-SQL inventory scanner + drift gate.

WHY THIS EXISTS
---------------
`apps/api/core/tenancy.py` auto-filters every ORM query by workspace, but raw SQL bypasses
that filter entirely -- so for raw statements the INVENTORY IS THE CONTROL. That inventory
lived only as a hand-maintained table in docs/architecture/mysql-migration-phase0.md, which
declared "Complete production inventory -- 9 sites" while the tree actually held 26. The doc
predicted its own failure ("A new `text()` call site could be added without updating section
7. No automated gate today -- this is the weakest link"). This script is that gate.

DETECTION IS AST-BASED, NOT GREP
--------------------------------
A substring search for "text(" is unusable here: it matches context(, _vuln_context(,
ciphertext(, read_text(, prose inside docstrings, and -- overwhelmingly -- the 47
`server_default=text("CURRENT_TIMESTAMP(6)")` column defaults, which are DDL, not queries.
Parsing the AST identifies genuine call sites structurally and yields a deterministic set
with no false positives.

WHAT COUNTS AS A SITE
---------------------
A call, in production code under apps/api, to any of:

  * `text(...)`                   -- SQLAlchemy textual SQL
  * `sqlalchemy.text(...)`        -- called through the module, not the bare name
  * an ALIAS of either            -- `from sqlalchemy import text as sql_text` / `import
                                     sqlalchemy as sa` -> `sa.text(...)`. Aliases are resolved
                                     per-file from the import statements, so renaming the
                                     import cannot hide a site (AUDIT-003).
  * `.exec_driver_sql(...)`       -- and any alias bound to it
  * `.execute(...)` / `.executemany(...)` ON A DBAPI CURSOR -- these bypass SQLAlchemy entirely.

...EXCEPT when the call is the value of a `server_default=` / `onupdate=` / `default=` keyword
(schema DDL, applied by the migration engine, never a tenant-scoped runtime query).

DISTINGUISHING A DBAPI CURSOR FROM AN ORM SESSION
-------------------------------------------------
`.execute(...)` is overwhelmingly the ORM's own `session.execute(select(...))`, which IS
tenancy-filtered and must NOT be flagged -- flagging it would bury the real sites in hundreds
of false positives and get the gate disabled. So a `.execute()` counts only when its receiver
is statically known to be a DBAPI cursor: a local name assigned from a `.cursor()` call
(`cur = conn.cursor()`), or a name that is literally cursor-ish (`cur`, `cursor`, `dbapi_cur`).
That is precisely the pymysql pattern this repo uses in observability.py and dr/service.py.
A cursor obtained in some other shape is caught by the companion runtime test that asserts the
known set of production sites, and by review.

EXCLUDED, DELIBERATELY:
  * apps/api/tests/**   -- fixtures legitimately craft raw SQL to set up state; they never
                           run in production and are not a tenancy surface.
  * db/migrations/**    -- Alembic runs as a schema owner by design, outside the request
                           path; migrations are reviewed as schema changes, not queries.
  * __pycache__, .venv, node_modules -- generated / vendored.

USAGE
    python scripts/raw_sql_inventory.py            # report the current inventory
    python scripts/raw_sql_inventory.py --check    # exit 1 on any drift (CI gate)
    python scripts/raw_sql_inventory.py --json     # machine-readable

REGISTERING A NEW SITE
    Add raw SQL only when the ORM genuinely cannot express it. Then add an entry to
    docs/architecture/raw-sql-inventory.yml with its classification and justification, and
    give any TENANT_SCOPED statement an explicit workspace predicate. Until it is registered,
    CI fails -- which is the point.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOT = REPO_ROOT / "apps" / "api"
INVENTORY = REPO_ROOT / "docs" / "architecture" / "raw-sql-inventory.yml"

# Callables that execute caller-supplied SQL. These are the CANONICAL names; per-file aliases
# are resolved back to them by _alias_map() so an `as` rename cannot smuggle a site past the gate.
RAW_SQL_CALLS = {"text", "exec_driver_sql"}
# Modules whose `.text` attribute is SQLAlchemy's textual-SQL constructor. Tracked so that
# `sa.text(...)` / `sqlalchemy.text(...)` resolve, while an unrelated `foo.text` does not.
SQLALCHEMY_MODULES = {"sqlalchemy"}
# DBAPI cursor methods that execute raw SQL, bypassing SQLAlchemy (and therefore the ORM
# tenancy filter) completely.
CURSOR_EXEC_METHODS = {"execute", "executemany"}
# Receiver names treated as a DBAPI cursor without needing an assignment to prove it.
CURSORISH_NAMES = {"cur", "cursor", "dbapi_cur", "dbapi_cursor", "_cur", "c_cur"}
# Keyword arguments whose value is schema DDL rather than a runtime query.
SCHEMA_KWARGS = {"server_default", "onupdate", "default"}
EXCLUDED_PARTS = {"tests", "__pycache__", ".venv", "node_modules", "migrations"}


def _excluded(path: Path) -> bool:
    return any(part in EXCLUDED_PARTS for part in path.parts)


def _alias_map(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    """Resolve this file's import aliases for the raw-SQL callables.

    Returns (name_aliases, module_aliases):
      * name_aliases maps a LOCAL name back to its canonical callable, so
        `from sqlalchemy import text as sql_text`      -> {"sql_text": "text"}
        `from sqlalchemy import exec_driver_sql as eds`-> {"eds": "exec_driver_sql"}
        A plain `from sqlalchemy import text` maps "text" -> "text" (identity).
      * module_aliases is the set of local names bound to the sqlalchemy module, so
        `import sqlalchemy as sa` -> {"sa"}, making `sa.text(...)` resolvable.

    Without this, renaming the import was enough to make a raw-SQL site invisible to the
    gate -- the AUDIT-003 finding.
    """
    name_aliases: dict[str, str] = {}
    module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in SQLALCHEMY_MODULES or a.name.split(".")[0] in SQLALCHEMY_MODULES:
                    module_aliases.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name in RAW_SQL_CALLS:
                    name_aliases[a.asname or a.name] = a.name
    return name_aliases, module_aliases


def _cursor_names(tree: ast.AST) -> set[str]:
    """Local names statically known to hold a DBAPI cursor.

    Anything assigned from a `.cursor()` call -- `cur = conn.cursor()`, and the `with
    conn.cursor() as cur:` form -- plus the conventional cursor names. Used to tell a raw
    `cursor.execute("...")` apart from the ORM's tenancy-filtered `session.execute(select(...))`.
    """
    names: set[str] = set(CURSORISH_NAMES)

    def _is_cursor_call(value: ast.AST) -> bool:
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "cursor"
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_cursor_call(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    names.add(tgt.id)
        elif isinstance(node, ast.AnnAssign) and node.value is not None and _is_cursor_call(node.value):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if _is_cursor_call(item.context_expr) and isinstance(item.optional_vars, ast.Name):
                    names.add(item.optional_vars.id)
    return names


def _callee_name(
    node: ast.Call,
    name_aliases: dict[str, str] | None = None,
    module_aliases: set[str] | None = None,
    cursor_names: set[str] | None = None,
) -> str | None:
    """The canonical raw-SQL mechanism this call invokes, or None if it is not one.

    Resolves through per-file import aliases and recognises DBAPI cursor execution. Called
    with no alias context it degrades to the original bare-name matching, which keeps it
    usable as a plain helper.
    """
    name_aliases = name_aliases or {}
    module_aliases = module_aliases or set()
    cursor_names = cursor_names or set()
    fn = node.func

    if isinstance(fn, ast.Name):
        # Bare call: `text(...)`, or an alias of it -- but ONLY if the alias was actually
        # imported in this file, so a local helper coincidentally named `text` is not assumed.
        if fn.id in name_aliases:
            return name_aliases[fn.id]
        if fn.id in RAW_SQL_CALLS:
            return fn.id
        return None

    if isinstance(fn, ast.Attribute):
        # `sa.text(...)` / `sqlalchemy.text(...)` -- module-qualified textual SQL.
        if fn.attr == "text" and isinstance(fn.value, ast.Name) and fn.value.id in module_aliases:
            return "text"
        # `.exec_driver_sql(...)` on any connection object.
        if fn.attr in RAW_SQL_CALLS:
            return fn.attr
        # `cur.execute(...)` / `cur.executemany(...)` on a statically-known DBAPI cursor.
        # Deliberately NOT every `.execute()`: session.execute(select(...)) is ORM-filtered.
        if fn.attr in CURSOR_EXEC_METHODS:
            recv = fn.value
            if isinstance(recv, ast.Name) and recv.id in cursor_names:
                return f"cursor.{fn.attr}"
            # `conn.cursor().execute(...)` -- chained, no intermediate name.
            if (
                isinstance(recv, ast.Call)
                and isinstance(recv.func, ast.Attribute)
                and recv.func.attr == "cursor"
            ):
                return f"cursor.{fn.attr}"
        return None

    return None


def scan(root: Path = SCAN_ROOT) -> list[dict]:
    """Every executable raw-SQL call site under `root`, sorted deterministically."""
    sites: list[dict] = []
    for path in sorted(root.rglob("*.py")):
        if _excluded(path):
            continue
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:  # a file that cannot parse cannot be audited -- surface it
            raise SystemExit(f"raw-sql-inventory: cannot parse {path}: {exc}") from exc

        # Calls used as schema DDL (server_default=text(...)) are not runtime queries.
        schema_call_ids = {
            id(kw.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            for kw in node.keywords
            if kw.arg in SCHEMA_KWARGS and isinstance(kw.value, ast.Call)
        }
        name_aliases, module_aliases = _alias_map(tree)
        cursor_names = _cursor_names(tree)
        lines = source.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or id(node) in schema_call_ids:
                continue
            name = _callee_name(node, name_aliases, module_aliases, cursor_names)
            if name is None:
                continue
            # Report repo-relative paths for the real tree. When `root` points elsewhere (the
            # mutation tests scan a synthetic tmp tree), relative_to(REPO_ROOT) would raise --
            # fall back to a path relative to the scan root so the scanner stays testable.
            try:
                rel = path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                rel = path.relative_to(root).as_posix()
            sites.append(
                {
                    "file": rel,
                    "line": node.lineno,
                    "mechanism": name,
                    "snippet": lines[node.lineno - 1].strip()[:100],
                }
            )
    sites.sort(key=lambda s: (s["file"], s["line"]))
    return sites


def load_inventory() -> dict[str, set[int]]:
    """Parse the inventory without a YAML dependency.

    The file is intentionally a flat `path:` / `- <line>` mapping so it can be read with the
    stdlib alone -- this gate must be runnable before any project dependency is installed.
    """
    if not INVENTORY.is_file():
        return {}
    registered: dict[str, set[int]] = {}
    current: str | None = None
    for raw in INVENTORY.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            current = stripped[:-1].strip()
            registered.setdefault(current, set())
        elif current is not None and stripped.startswith("- "):
            token = stripped[2:].split()[0].rstrip(":")
            if token.isdigit():
                registered[current].add(int(token))
    return registered


def check() -> int:
    """Compare the tree against the registered inventory. 0 = in sync, 1 = drift."""
    actual = scan()
    registered = load_inventory()

    actual_map: dict[str, set[int]] = {}
    for site in actual:
        actual_map.setdefault(site["file"], set()).add(site["line"])
    by_key = {(s["file"], s["line"]): s for s in actual}

    unregistered = [
        by_key[(f, ln)]
        for f in sorted(actual_map)
        for ln in sorted(actual_map[f] - registered.get(f, set()))
    ]
    missing = [
        (f, ln)
        for f in sorted(registered)
        for ln in sorted(registered[f] - actual_map.get(f, set()))
    ]

    if not unregistered and not missing:
        print(
            f"raw-sql-inventory: OK -- {len(actual)} production raw-SQL sites, all registered."
        )
        return 0

    total_registered = sum(len(v) for v in registered.values())
    print("raw-sql-inventory: DRIFT DETECTED", file=sys.stderr)
    print(f"  registered: {total_registered}   actual: {len(actual)}", file=sys.stderr)

    if unregistered:
        print(
            "\n  UNREGISTERED raw SQL (a new site, or a registered one that moved):",
            file=sys.stderr,
        )
        for s in unregistered:
            print(
                f"    {s['file']}:{s['line']}  [{s['mechanism']}]  {s['snippet']}",
                file=sys.stderr,
            )
        print(
            "\n  Raw SQL bypasses the ORM tenancy filter (apps/api/core/tenancy.py), so every\n"
            "  statement must be reviewed. If it is intentional: give any tenant-scoped\n"
            "  statement an explicit workspace predicate, then register it in\n"
            f"  {INVENTORY.relative_to(REPO_ROOT).as_posix()}.",
            file=sys.stderr,
        )
    if missing:
        print(
            "\n  REGISTERED BUT NOT FOUND (removed or moved -- update the inventory):",
            file=sys.stderr,
        )
        for f, ln in missing:
            print(f"    {f}:{ln}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Raw-SQL inventory scanner + drift gate.",
    )
    parser.add_argument(
        "--check", action="store_true", help="exit 1 on inventory drift (CI gate)"
    )
    parser.add_argument("--json", action="store_true", help="emit the inventory as JSON")
    args = parser.parse_args()

    if args.check:
        return check()

    sites = scan()
    if args.json:
        print(json.dumps(sites, indent=2))
    else:
        for site in sites:
            print(
                f"{site['file']}:{site['line']}  [{site['mechanism']}]  {site['snippet']}"
            )
        print(f"\n{len(sites)} production raw-SQL sites.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
