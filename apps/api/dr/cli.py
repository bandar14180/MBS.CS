"""Phase 1.6 -- DR command-line entry. Returns proper exit codes (0 success, non-zero
failure) so it composes with cron / systemd / CI.

  python -m apps.api.dr backup
  python -m apps.api.dr verify   <set_dir>
  python -m apps.api.dr restore  <set_dir> [--target-db-url URL] [--objects]
  python -m apps.api.dr cleanup
"""
import argparse
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
    sub.add_parser("cleanup", help="apply retention/cleanup to the backup directory")

    args = parser.parse_args(argv)
    settings = get_settings()

    if args.cmd == "backup":
        return 0 if service.run_backup(settings).ok else 1
    if args.cmd == "verify":
        return 0 if service.verify_backup(args.set_dir) else 1
    if args.cmd == "restore":
        ok = service.run_restore(
            settings, args.set_dir,
            target_database_url=args.target_db_url, include_objects=args.objects,
        )
        return 0 if ok else 1
    if args.cmd == "cleanup":
        service.cleanup_old_backups(settings)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
