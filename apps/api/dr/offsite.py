"""DR-3 -- off-site backup replication (provider-agnostic).

A backup only protects against infrastructure loss if a copy lives OFF the host. This module
replicates a completed, verified backup set to an off-site target through a small injectable
interface, so the DR flow never hard-codes a cloud provider and stays fully unit-testable with
an in-memory fake.

Two built-in providers:
  * local -- copy the set to a mounted/off-host directory (NFS, second disk, sync mount).
  * s3    -- upload to ANY S3-compatible endpoint (AWS S3, MinIO, Wasabi, Backblaze B2, ...);
             the endpoint/credentials are configurable, never AWS-specific.

Both are selected by `backup_offsite_provider`; add more by implementing `OffsiteTarget`.
"""
import shutil
from pathlib import Path
from typing import Protocol


class OffsiteTarget(Protocol):
    def replicate_set(self, set_dir: Path) -> int:
        """Copy every file of one backup set off-site. Returns the number of files replicated."""
        ...


class LocalOffsiteTarget:
    """Replicate to a mounted off-host directory. Provider-agnostic: whatever is mounted at
    `base_dir` (NFS, rsync/rclone mount, second physical disk) receives a faithful copy."""

    def __init__(self, base_dir: str):
        if not base_dir:
            raise RuntimeError("BACKUP_OFFSITE_DIR is required for the 'local' offsite provider")
        self._base = Path(base_dir)

    def replicate_set(self, set_dir) -> int:
        set_dir = Path(set_dir)
        dest = self._base / set_dir.name
        dest.mkdir(parents=True, exist_ok=True)
        count = 0
        for f in sorted(set_dir.iterdir()):
            if f.is_file():
                shutil.copy2(f, dest / f.name)
                count += 1
        return count


class S3OffsiteTarget:
    """Replicate to any S3-compatible object store. `endpoint_url` blank -> AWS default; set it
    to a MinIO/Wasabi/B2 endpoint for those. Credentials fall back to the app's S3_* settings
    when the dedicated offsite ones are blank. boto3 is imported lazily."""

    def __init__(self, settings):
        import boto3
        from botocore.config import Config

        if not settings.backup_offsite_bucket:
            raise RuntimeError("BACKUP_OFFSITE_BUCKET is required for the 's3' offsite provider")
        self._bucket = settings.backup_offsite_bucket
        self._prefix = (settings.backup_offsite_prefix or "").strip("/")
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.backup_offsite_endpoint_url or None,
            aws_access_key_id=settings.backup_offsite_access_key or settings.s3_access_key,
            aws_secret_access_key=settings.backup_offsite_secret_key or settings.s3_secret_key,
            region_name=settings.backup_offsite_region,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    def _key(self, set_name: str, filename: str) -> str:
        return "/".join(p for p in (self._prefix, set_name, filename) if p)

    def replicate_set(self, set_dir) -> int:
        set_dir = Path(set_dir)
        count = 0
        for f in sorted(set_dir.iterdir()):
            if f.is_file():
                self._client.upload_file(str(f), self._bucket, self._key(set_dir.name, f.name))
                count += 1
        return count


def get_offsite_target(settings) -> OffsiteTarget:
    """Factory: build the configured off-site target. Unknown provider -> hard error."""
    provider = (getattr(settings, "backup_offsite_provider", "local") or "local").lower()
    if provider == "local":
        return LocalOffsiteTarget(settings.backup_offsite_dir)
    if provider == "s3":
        return S3OffsiteTarget(settings)
    raise RuntimeError(f"unknown BACKUP_OFFSITE_PROVIDER: {provider!r} (expected 'local' or 's3')")
