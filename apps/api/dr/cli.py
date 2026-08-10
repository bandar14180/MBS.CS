"""Phase 1.6 -- DR command-line entry. Returns proper exit codes (0 success, non-zero
failure) so it composes with cron / systemd / CI.

  python -m apps.api.dr backup
  python -m apps.api.dr verify   <set_dir>
  python -m apps.api.dr restore  <set_dir> [--target-db-url URL] [--objects]
  python -m apps.api.dr drill    [--set <set_dir>] [--target-db-url URL] [--objects]
  python -m apps.api.dr cleanup
"""
import argparse
import json
import sys

from apps.api.core.config import get_settings
from apps.api.dr import service


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="apps.api.dr", description="MBS disaster recovery")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup", help="create a new backup set")
    p_verify = sub.add_parser("verify", help="verify an existing backup set")
    p_verify.add_argument("set_dir")
    p_restore = sub.add_parser("restore", help="restore a backup set")
    p_restore.add_argument("set_dir")
    p_restore.add_argument("--target-db-url", default=None, help="restore into this DB instead of the configured one")
    p_restore.add_argument("--objects", action="store_true", help="also restore object storage")
    p_drill = sub.add_parser("drill", help="DR-4: restore the latest set into a scratch DB + smoke checks")
    p_drill.add_argument("--set", dest="set_dir", default=None, help="drill this set (default: latest)")
    p_drill.add_argument("--target-db-url", default=None, help="scratch DB to restore into (never the live DB)")
    p_drill.add_argument("--objects", action="store_true", help="also restore object storage in the drill")
    sub.add_parser("cleanup", help="apply retention/cleanup to the backup directory")

    args = parser.parse_args(argv)
    settings = get_settings()

    if args.cmd == "backup":
        return 0 if service.run_backup(settings).ok else 1
    if args.cmd == "verify":
        return 0 if service.verify_backup(args.set_dir, settings=settings) else 1
    if args.cmd == "restore":
        ok = service.run_restore(
            settings, args.set_dir,
            target_database_url=args.target_db_url, include_objects=args.objects,
        )
        return 0 if ok else 1
    if args.cmd == "drill":
        report = service.run_drill(
            settings, set_dir=args.set_dir,
            target_database_url=args.target_db_url, include_objects=args.objects,
        )
        # Print the evidence report path + summary to stdout for CI/operator capture.
        print(json.dumps({
            "set": report.set_name, "verified": report.verified, "restored": report.restored,
            "checks": report.checks, "ok": report.ok, "report": report.report_path,
        }, indent=2, sort_keys=True))
        return 0 if report.ok else 1
    if args.cmd == "cleanup":
        service.cleanup_old_backups(settings)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
