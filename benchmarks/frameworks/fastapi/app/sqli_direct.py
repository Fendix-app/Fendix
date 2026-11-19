import sqlite3
from contextlib import closing

from fastapi import APIRouter

router = APIRouter()

DB_PATH = "app.db"


@router.get("/sqli/direct")
def search_users(username: str = ""):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email FROM users WHERE username = '{username}'")  # EVAL-SINK
        rows = cursor.fetchall()
    return {"results": [list(row) for row in rows]}
