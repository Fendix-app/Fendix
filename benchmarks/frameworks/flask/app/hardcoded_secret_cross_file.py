import boto3
from flask import jsonify

from app.blueprint import bp
from app.services.aws_config import AWS_ACCESS_KEY_ID, AWS_REGION, AWS_SECRET_ACCESS_KEY

UPLOAD_BUCKET = "media-uploads"


@bp.route("/hardcoded-secret/cross-file", endpoint="hardcoded_secret_cross_file")
def list_uploads():
    s3 = boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    response = s3.list_objects_v2(Bucket=UPLOAD_BUCKET, MaxKeys=50)
    return jsonify(keys=[obj["Key"] for obj in response.get("Contents", [])])
