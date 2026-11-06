from flask import jsonify

from app.blueprint import bp

# SHA-256 digest of the release artifact, stamped in by the build pipeline.
BUILD_DIGEST = "3f9c2a7e51d08b64c7e2f91a0b5d38e6a4f17c29e8360d5b92c4a7f16e0b3d85"  # EVAL-SAFE


@bp.route("/hardcoded-secret/safe-lookalike", endpoint="hardcoded_secret_safe_lookalike")
def build_info():
    return jsonify(build_digest=BUILD_DIGEST)
