import os

import jwt
from django.http import JsonResponse

SIGNING_KEYS = {
    "primary": os.environ.get("JWT_PRIMARY_KEY", ""),
    "previous": os.environ.get("JWT_PREVIOUS_KEY", ""),
}


def current_user(request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        kid = jwt.get_unverified_header(token).get("kid", "")  # EVAL-SAFE
        claims = jwt.decode(token, SIGNING_KEYS[kid], algorithms=["HS256"])
    except (jwt.InvalidTokenError, KeyError):
        return JsonResponse({"error": "invalid token"}, status=401)
    return JsonResponse({"user_id": claims.get("sub"), "role": claims.get("role")})
