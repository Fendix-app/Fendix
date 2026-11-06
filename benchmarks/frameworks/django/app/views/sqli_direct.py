from django.db import connection
from django.http import JsonResponse


def search_users(request):
    username = request.GET.get("username", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, username, email FROM auth_user WHERE username = '{username}'")  # EVAL-SINK
        rows = cursor.fetchall()
    return JsonResponse({"results": [list(row) for row in rows]})
