"""Object-storage provider interface (P2-11).

A seam so evidence/report artifacts can live on MinIO/S3 today and Azure Blob or
GCS later, selected by STORAGE_PROVIDER -- without callers knowing the backend.
Additive: the existing evidence_store / reports.storage functions are unchanged;
the S3 provider reuses their client helpers so credentials/behavior are identical.
"""
from abc import ABC, abstractmethod

from apps.api.core.config import get_settings


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
