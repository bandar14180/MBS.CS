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
