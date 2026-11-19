import jwt
from django.http import JsonResponse


def current_user(request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, options={"verify_signature": False})  # EVAL-SINK
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "invalid token"}, status=401)
    return JsonResponse({"user_id": claims.get("sub"), "role": claims.get("role")})
