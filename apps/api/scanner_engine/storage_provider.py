"""Object-storage provider interface (P2-11).

A seam so evidence/report artifacts can live on MinIO/S3 today and Azure Blob or
GCS later, selected by STORAGE_PROVIDER -- without callers knowing the backend.
Additive: the existing evidence_store / reports.storage functions are unchanged;
the S3 provider reuses their client helpers so credentials/behavior are identical.
"""
import logging
from abc import ABC, abstractmethod

from apps.api.core.config import get_settings

logger = logging.getLogger(__name__)


def _validate_key(key: str) -> str:
    """Guard an object key before any destructive op. Object storage is key-addressed
    (not a filesystem), but we still refuse path-traversal / absolute / NUL-byte inputs so
    a caller can never be tricked into touching an object outside the intended key."""
    if not isinstance(key, str):
        raise ValueError("storage key must be a string")
    cleaned = key.strip()
    if not cleaned:
        raise ValueError("storage key must be a non-empty string")
    if "\x00" in cleaned or ".." in cleaned or cleaned.startswith("/") or "\\" in cleaned:
        raise ValueError(f"unsafe storage key: {key!r}")
    return cleaned


def _validate_prefix(prefix: str) -> str:
    """As _validate_key, plus the critical guard that a prefix must be SPECIFIC: an empty
    or all-slash prefix would enumerate and delete an ENTIRE bucket, so we refuse it."""
    if not isinstance(prefix, str):
        raise ValueError("storage prefix must be a string")
    cleaned = prefix.strip()
    if not cleaned or not cleaned.strip("/"):
        raise ValueError(
            "storage prefix must be a non-empty, specific value "
            "(refusing to enumerate/delete an entire bucket)"
        )
    if "\x00" in cleaned or ".." in cleaned or cleaned.startswith("/") or "\\" in cleaned:
        raise ValueError(f"unsafe storage prefix: {prefix!r}")
    return cleaned


class StorageProvider(ABC):
    """Store and fetch opaque artifacts by key. Concrete backends: S3/MinIO
    (default); Azure Blob and GCS are future implementations behind this same
    interface."""

    name: str = "base"

    @abstractmethod
    def put(self, key: str, content: bytes, content_type: str = "application/octet-stream") -> str:
        """Store `content` under `key`; return a stable storage URI."""

    @abstractmethod
    def get(self, key: str) -> bytes:
        """Fetch the bytes previously stored under `key`."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete the object at `key`. Idempotent: deleting a missing object is a no-op,
        never an error (safe for retries and already-cleaned artifacts)."""

    @abstractmethod
    def delete_prefix(self, prefix: str) -> int:
        """Delete every object whose key starts with `prefix`; return the count deleted.
        A prefix that matches nothing returns 0. `prefix` must be specific (never empty)."""


class S3StorageProvider(StorageProvider):
    """MinIO / AWS S3 compatible. Self-contained boto3 client (same endpoint /
    credentials / signature as the rest of the platform), so callers depend on this
    interface rather than reaching into another module's private helpers."""

    name = "s3"

    def __init__(self, bucket: str | None = None):
        self._bucket = bucket or get_settings().s3_bucket_evidence

    def _client(self):
        import boto3
        from botocore.client import Config
        from botocore.exceptions import ClientError

        s = get_settings()
        client = boto3.client(
            "s3",
            endpoint_url=s.s3_endpoint_url,
            aws_access_key_id=s.s3_access_key,
            aws_secret_access_key=s.s3_secret_key,
            config=Config(signature_version="s3v4"),
            region_name="us-east-1",
        )
        try:
            client.head_bucket(Bucket=self._bucket)
        except ClientError:
            client.create_bucket(Bucket=self._bucket)
        return client

    def put(self, key: str, content: bytes, content_type: str = "application/octet-stream") -> str:
        self._client().put_object(Bucket=self._bucket, Key=key, Body=content, ContentType=content_type)
        return f"s3://{self._bucket}/{key}"

    def get(self, key: str) -> bytes:
        return self._client().get_object(Bucket=self._bucket, Key=key)["Body"].read()

    def delete(self, key: str) -> None:
        from botocore.exceptions import ClientError

        key = _validate_key(key)
        logger.info("storage.delete attempt bucket=%s key=%s", self._bucket, key)
        try:
            self._client().delete_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            # Already gone -> idempotent success. S3 normally returns 200 for a missing
            # key; MinIO / other backends may surface NoSuchKey/404, which we treat the same.
            if code in ("NoSuchKey", "NoSuchBucket", "404"):
                logger.info("storage.delete noop-missing bucket=%s key=%s code=%s", self._bucket, key, code)
                return
            logger.error("storage.delete failed bucket=%s key=%s code=%s", self._bucket, key, code)
            raise
        logger.info("storage.delete ok bucket=%s key=%s", self._bucket, key)

    def delete_prefix(self, prefix: str) -> int:
        prefix = _validate_prefix(prefix)
        client = self._client()
        logger.info("storage.delete_prefix attempt bucket=%s prefix=%s", self._bucket, prefix)
        deleted = 0
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            contents = page.get("Contents") or []
            if not contents:
                continue
            # delete_objects caps at 1000 keys/call; a list_objects_v2 page is already <= 1000.
            client.delete_objects(
                Bucket=self._bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in contents], "Quiet": True},
            )
            deleted += len(contents)
        logger.info("storage.delete_prefix ok bucket=%s prefix=%s deleted=%d", self._bucket, prefix, deleted)
        return deleted


def get_storage_provider(bucket: str | None = None) -> StorageProvider:
    """Return the configured StorageProvider. Unknown / not-yet-implemented
    backends raise a clear error rather than silently mis-storing."""
    backend = get_settings().storage_provider
    if backend in ("s3", "minio"):
        return S3StorageProvider(bucket)
    raise NotImplementedError(
        f"Storage backend '{backend}' is not implemented yet (available: s3/minio; "
        f"azure_blob/gcs are planned behind the StorageProvider interface)."
    )
