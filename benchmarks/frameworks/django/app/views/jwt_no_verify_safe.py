import os

import jwt
from django.http import JsonResponse

JWT_SECRET = os.environ["JWT_SECRET"]


def current_user(request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # EVAL-SAFE
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "invalid token"}, status=401)
    return JsonResponse({"user_id": claims.get("sub"), "role": claims.get("role")})
