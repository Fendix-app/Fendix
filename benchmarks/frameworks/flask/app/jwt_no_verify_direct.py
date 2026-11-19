import jwt
from flask import jsonify, request

from app.blueprint import bp


@bp.route("/jwt-no-verify/direct", endpoint="jwt_no_verify_direct")
def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, options={"verify_signature": False})  # EVAL-SINK
    except jwt.InvalidTokenError:
        return jsonify(error="invalid token"), 401
    return jsonify(user_id=claims.get("sub"), role=claims.get("role"))
