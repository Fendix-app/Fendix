from django.contrib.auth.hashers import make_password
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def register(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    password_hash = make_password(password)  # EVAL-SAFE
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (%s, %s)",
            [username, password_hash],
        )
    return JsonResponse({"created": username}, status=201)
