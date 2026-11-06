from django.db import connection
from django.http import JsonResponse

USERS_TABLE = "auth_user"


def list_active_users(request):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, username, email FROM {USERS_TABLE} WHERE is_active = 1 ORDER BY username")  # EVAL-SAFE
        rows = cursor.fetchall()
    return JsonResponse({"results": [list(row) for row in rows]})
