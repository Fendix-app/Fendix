import os

import boto3
from fastapi import APIRouter

router = APIRouter()

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")  # EVAL-SAFE
UPLOAD_BUCKET = "media-uploads"


@router.get("/hardcoded-secret/safe")
def list_uploads():
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    response = s3.list_objects_v2(Bucket=UPLOAD_BUCKET, MaxKeys=50)
    return {"keys": [obj["Key"] for obj in response.get("Contents", [])]}
