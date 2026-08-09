#!/usr/bin/env python3
"""Backup / restore / verify the MBS object-storage buckets (evidence + reports).

Portable across MinIO and AWS S3 (path-style + s3v4). Credentials are read ONLY from
the environment (or *_FILE indirection, matching the app's secret handling) -- never
from CLI args (which leak via `ps`). Additive tooling: it does not import or modify the
application; it only reads/writes object storage.

Usage:
  object_store.py backup  <dest_dir>     # download every object -> dest_dir/<bucket>/<key> + CHECKSUMS.sha256
  object_store.py verify  <dir>          # recompute checksums vs CHECKSUMS.sha256
  object_store.py restore <src_dir>      # upload objects back (creates buckets if absent)

Env: S3_ENDPOINT_URL (http://minio:9000), S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION,
     S3_BUCKET_EVIDENCE (mbs-evidence), S3_BUCKET_REPORTS (mbs-reports).
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import boto3
from botocore.config import Config


def _secret(name, default=None):
    fp = os.environ.get(name + "_FILE")
    if fp and Path(fp).exists():
        return Path(fp).read_text(encoding="utf-8").strip()
    return os.environ.get(name, default)


def _client():
    return boto3.client(
        "s3",
        endpoint_url=_secret("S3_ENDPOINT_URL", "http://minio:9000"),
        aws_access_key_id=_secret("S3_ACCESS_KEY", "minioadmin"),
        aws_secret_access_key=_secret("S3_SECRET_KEY", "minioadmin"),
        region_name=os.environ.get("S3_REGION", "us-east-1"),
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def _buckets():
    return [b for b in (
        os.environ.get("S3_BUCKET_EVIDENCE", "mbs-evidence"),
        os.environ.get("S3_BUCKET_REPORTS", "mbs-reports"),
    ) if b]


def _keys(client, bucket):
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            yield obj["Key"]


def backup(dest):
    client = _client()
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    sums, total = {}, 0
    for bucket in _buckets():
        try:
            keys = list(_keys(client, bucket))
        except Exception as exc:  # noqa: BLE001 -- a missing bucket must not abort the whole backup
            print(f"[warn] bucket '{bucket}' not readable: {exc}", file=sys.stderr)
            continue
        for key in keys:
            out = dest / bucket / key
            out.parent.mkdir(parents=True, exist_ok=True)
            client.download_file(bucket, key, str(out))
            sums[f"{bucket}/{key}"] = hashlib.sha256(out.read_bytes()).hexdigest()
            total += 1
    (dest / "CHECKSUMS.sha256").write_text(
        "".join(f"{v}  {k}\n" for k, v in sorted(sums.items())), encoding="utf-8"
    )
    print(json.dumps({"objects": total, "buckets": _buckets(), "dest": str(dest)}))
    return 0


def verify(d):
    d = Path(d)
    manifest = d / "CHECKSUMS.sha256"
    if not manifest.exists():
        print(json.dumps({"error": "CHECKSUMS.sha256 missing"}))
        return 1
    checked, bad = 0, 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        want, rel = line.split("  ", 1)
        checked += 1
        p = d / rel
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != want:
            bad += 1
            print(f"[MISMATCH] {rel}", file=sys.stderr)
    print(json.dumps({"checked": checked, "mismatches": bad}))
    return 1 if bad else 0


def restore(src):
    client = _client()
    src = Path(src)
    total = 0
    for bucket in _buckets():
        base = src / bucket
        if not base.exists():
            continue
        try:
            client.head_bucket(Bucket=bucket)
        except Exception:  # noqa: BLE001
            try:
                client.create_bucket(Bucket=bucket)
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] cannot create bucket '{bucket}': {exc}", file=sys.stderr)
        for p in base.rglob("*"):
            if p.is_file():
                key = str(p.relative_to(base)).replace(os.sep, "/")
                client.upload_file(str(p), bucket, key)
                total += 1
    print(json.dumps({"restored": total}))
    return 0


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("backup", "restore", "verify"):
        print(__doc__)
        return 2
    return {"backup": backup, "restore": restore, "verify": verify}[sys.argv[1]](sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
