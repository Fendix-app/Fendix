from django.db import connection
from django.http import JsonResponse


def _find_users(username: str) -> list:
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, username, email FROM auth_user WHERE username = '{username}'")  # EVAL-SINK
        return cursor.fetchall()


def search_users(request):
    username = request.GET.get("username", "")
    rows = _find_users(username)
    return JsonResponse({"results": [list(row) for row in rows]})
