import hashlib
import uuid

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from apps.api.core.config import get_settings


def _get_s3_client():
    settings = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def _ensure_bucket(client, bucket: str) -> None:
    try:
        client.head_bucket(Bucket=bucket)
    except ClientError:
        client.create_bucket(Bucket=bucket)


def store_raw_output(tool_run_id: uuid.UUID, content: bytes, content_type: str = "text/plain") -> tuple[str, str]:
    """Uploads raw tool output to the evidence bucket. Returns (storage_uri, sha256_checksum)."""
    settings = get_settings()
    client = _get_s3_client()
    _ensure_bucket(client, settings.s3_bucket_evidence)

    checksum = hashlib.sha256(content).hexdigest()
    key = f"tool-runs/{tool_run_id}/raw-output.txt"
    client.put_object(Bucket=settings.s3_bucket_evidence, Key=key, Body=content, ContentType=content_type)

    return f"s3://{settings.s3_bucket_evidence}/{key}", checksum


def store_screenshot(vulnerability_id: uuid.UUID, content: bytes) -> tuple[str, str]:
    """Upload a PNG screenshot for one vulnerability. Returns (storage_uri, sha256_checksum).

    Keyed by vulnerability + content checksum, which gives three things for free:
      * the object is addressable per FINDING, not just per tool run;
      * re-capturing an unchanged page overwrites the same key instead of accumulating
        near-duplicate objects across re-scans (the write is idempotent);
      * the checksum in the key is the same value stored on the Evidence row, so the report
        layer can deduplicate byte-identical screenshots without downloading them.

    Mirrors store_raw_output (same bucket, same client, same return shape) so evidence
    handling stays uniform. Binary-safe: the content type is image/png, not text."""
    settings = get_settings()
    client = _get_s3_client()
    _ensure_bucket(client, settings.s3_bucket_evidence)

    checksum = hashlib.sha256(content).hexdigest()
    key = f"vulnerabilities/{vulnerability_id}/screenshot-{checksum[:16]}.png"
    client.put_object(
        Bucket=settings.s3_bucket_evidence, Key=key, Body=content, ContentType="image/png"
    )

    return f"s3://{settings.s3_bucket_evidence}/{key}", checksum
