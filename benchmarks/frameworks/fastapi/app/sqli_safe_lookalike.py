import sqlite3
from contextlib import closing

from fastapi import APIRouter

router = APIRouter()

DB_PATH = "app.db"
USERS_TABLE = "users"


@router.get("/sqli/safe-lookalike")
def list_active_users():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email FROM {USERS_TABLE} WHERE is_active = 1 ORDER BY username")  # EVAL-SAFE
        rows = cursor.fetchall()
    return {"results": [list(row) for row in rows]}
