import jwt
from flask import jsonify, request

from app.blueprint import bp


def _decode_token(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})  # EVAL-SINK


@bp.route("/jwt-no-verify/indirect", endpoint="jwt_no_verify_indirect")
def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = _decode_token(token)
    except jwt.InvalidTokenError:
        return jsonify(error="invalid token"), 401
    return jsonify(user_id=claims.get("sub"), role=claims.get("role"))
