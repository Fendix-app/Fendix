import boto3
from flask import jsonify

from app.blueprint import bp

AWS_ACCESS_KEY_ID = "__EVAL_AWS_ACCESS_KEY_ID__"
AWS_SECRET_ACCESS_KEY = "__EVAL_AWS_SECRET_ACCESS_KEY__"  # EVAL-SINK
UPLOAD_BUCKET = "media-uploads"


@bp.route("/hardcoded-secret/direct", endpoint="hardcoded_secret_direct")
def list_uploads():
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    response = s3.list_objects_v2(Bucket=UPLOAD_BUCKET, MaxKeys=50)
    return jsonify(keys=[obj["Key"] for obj in response.get("Contents", [])])
