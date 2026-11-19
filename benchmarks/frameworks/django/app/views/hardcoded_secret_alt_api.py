import psycopg
from django.http import JsonResponse

REPORTING_DATABASE_URL = "postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app"  # EVAL-SINK


def order_stats(request):
    with psycopg.connect(REPORTING_DATABASE_URL) as conn:
        row = conn.execute("SELECT count(*) FROM orders").fetchone()
    return JsonResponse({"orders": row[0]})
