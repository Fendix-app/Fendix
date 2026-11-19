import os

import jwt
from flask import jsonify, request

from app.blueprint import bp

JWT_SECRET = os.environ["JWT_SECRET"]


@bp.route("/jwt-no-verify/safe", endpoint="jwt_no_verify_safe")
def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # EVAL-SAFE
    except jwt.InvalidTokenError:
        return jsonify(error="invalid token"), 401
    return jsonify(user_id=claims.get("sub"), role=claims.get("role"))
