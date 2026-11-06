import os

import jwt
from flask import jsonify, request

from app.blueprint import bp

SIGNING_KEYS = {
    "primary": os.environ.get("JWT_PRIMARY_KEY", ""),
    "previous": os.environ.get("JWT_PREVIOUS_KEY", ""),
}


@bp.route("/jwt-no-verify/safe-lookalike", endpoint="jwt_no_verify_safe_lookalike")
def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        kid = jwt.get_unverified_header(token).get("kid", "")  # EVAL-SAFE
        claims = jwt.decode(token, SIGNING_KEYS[kid], algorithms=["HS256"])
    except (jwt.InvalidTokenError, KeyError):
        return jsonify(error="invalid token"), 401
    return jsonify(user_id=claims.get("sub"), role=claims.get("role"))
