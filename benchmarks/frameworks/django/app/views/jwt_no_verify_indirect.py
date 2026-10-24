import jwt
from django.http import JsonResponse


def _decode_token(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})  # EVAL-SINK


def current_user(request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = _decode_token(token)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "invalid token"}, status=401)
    return JsonResponse({"user_id": claims.get("sub"), "role": claims.get("role")})
