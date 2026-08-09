"""Phase 5.2 -- retention manual entry point (mirrors the apps.api.dr CLI). Read-only /
dry-run only in this phase; it never deletes.

  python -m apps.api.retention plan       # print the retention plan (windows + cutoffs); no DB
  python -m apps.api.retention dry-run     # count eligible per resource; delete nothing
  python -m apps.api.retention run         # LIVE purge -- honors retention_enabled + retention_dry_run

`run` deletes only when retention_enabled=True AND retention_dry_run=False (the gates are never
bypassed); otherwise it is a no-op / dry-run. `plan` is pure (no DB); `dry-run`/`run` touch the DB.
"""
import argparse
import sys

from apps.api.core.config import get_settings
from apps.api.retention import service


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="apps.api.retention", description="MBS retention (foundation)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan", help="print the retention plan (per-resource window + cutoff); no deletion")
    sub.add_parser("dry-run", help="count eligible per resource; deletes nothing")
    sub.add_parser("run", help="LIVE purge -- honors retention_enabled + retention_dry_run gates")

    args = parser.parse_args(argv)
    settings = get_settings()

    if args.cmd == "plan":
        plans = service.build_plan(settings)
        print(
            f"retention_enabled={settings.retention_enabled} "
            f"retention_dry_run={settings.retention_dry_run} "
            f"batch_size={settings.retention_batch_size} min_keep={settings.retention_min_keep}"
        )
        for p in plans:
            print(
                f"  {p.resource:<14} keep<{p.retention_days:>4}d  cutoff={p.cutoff.date()}  "
                f"would_delete={p.eligible}  ({p.description})"
            )
        print("note: eligibility counting + deletion arrive in Phase 5.3 (would_delete is 0 here).")
        return 0

    if args.cmd == "dry-run":
        result = service.run_purge(settings, dry_run=True)
        print(f"mode={result.mode} dry_run={result.dry_run} total_would_delete={result.total_eligible}")
        for p in result.plans:
            print(f"  {p.resource:<14} would_delete={p.eligible}  (older than {p.cutoff.date()})")
        return 0

    if args.cmd == "run":
        # Honors the settings gates: live only when retention_enabled AND not retention_dry_run.
        result = service.run_purge(settings)
        print(f"mode={result.mode} total_eligible={result.total_eligible} total_deleted={result.total_deleted}")
        for p in result.plans:
            print(f"  {p.resource:<14} eligible={p.eligible}  deleted={p.deleted}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
