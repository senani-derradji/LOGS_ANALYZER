import boto3
import json
import time
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from app.core.config import settings

ENDPOINT = settings.CLOUDFLARE_URL
ACCESS_KEY = settings.CLOUDFLARE_ACCOUNT_ID
SECRET_KEY = settings.CLOUDFLARE_API_TOKEN
BUCKET = settings.CLOUDFLARE_BUCKET

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name="auto",
    config=Config(
        retries={"max_attempts": 5, "mode": "standard"},
        connect_timeout=5,
        read_timeout=30,
    ),
)


def upload_stream_to_r2(file_path, user_prefix: str, filename: str, user_id: int):
    key = f"logs/{user_prefix}/{user_id}/{filename}"

    # IMPORTANT FIX HERE 👇
    with open(file_path, "rb") as f:
        s3.upload_fileobj(
            Fileobj=f,
            Bucket=BUCKET,
            Key=key,
            ExtraArgs={
                "ContentType": "application/octet-stream"
            }
        )

    return key