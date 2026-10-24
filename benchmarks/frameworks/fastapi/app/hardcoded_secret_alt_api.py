import psycopg
from fastapi import APIRouter

router = APIRouter()

REPORTING_DATABASE_URL = "postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app"  # EVAL-SINK


@router.get("/hardcoded-secret/alt-api")
def order_stats():
    with psycopg.connect(REPORTING_DATABASE_URL) as conn:
        row = conn.execute("SELECT count(*) FROM orders").fetchone()
    return {"orders": row[0]}
