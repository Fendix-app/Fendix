from django.db import connection


def find_users(username: str) -> list:
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, username, email FROM auth_user WHERE username = '{username}'")  # EVAL-SINK
        return cursor.fetchall()
