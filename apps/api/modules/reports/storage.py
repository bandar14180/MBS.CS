import uuid

from apps.api.core.config import get_settings
from apps.api.scanner_engine.storage_provider import get_storage_provider


def store_report(report_id: uuid.UUID, content: bytes, content_type: str = "application/pdf") -> str:
    """Persist a rendered report to object storage via the StorageProvider
    interface (no dependency on another module's private client helpers)."""
    bucket = get_settings().s3_bucket_reports
    key = f"reports/{report_id}.pdf"
    return get_storage_provider(bucket).put(key, content, content_type)


def fetch_report(storage_uri: str) -> bytes:
    _, _, rest = storage_uri.partition("s3://")
    bucket, _, key = rest.partition("/")
    return get_storage_provider(bucket).get(key)
