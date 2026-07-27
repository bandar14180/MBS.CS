import uuid

from apps.api.core.config import get_settings
# Reuse the object-storage client/bucket helpers from the evidence store rather
# than duplicating boto3 setup.
from apps.api.scanner_engine.evidence_store import _ensure_bucket, _get_s3_client


def store_report(report_id: uuid.UUID, content: bytes, content_type: str = "application/pdf") -> str:
    settings = get_settings()
    client = _get_s3_client()
    _ensure_bucket(client, settings.s3_bucket_reports)
    key = f"reports/{report_id}.pdf"
    client.put_object(Bucket=settings.s3_bucket_reports, Key=key, Body=content, ContentType=content_type)
    return f"s3://{settings.s3_bucket_reports}/{key}"


def fetch_report(storage_uri: str) -> bytes:
    client = _get_s3_client()
    _, _, rest = storage_uri.partition("s3://")
    bucket, _, key = rest.partition("/")
    obj = client.get_object(Bucket=bucket, Key=key)
    return obj["Body"].read()
