import sqlite3
from contextlib import closing

from fastapi import APIRouter

router = APIRouter()

DB_PATH = "app.db"


def _find_users(username: str) -> list:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email FROM users WHERE username = '{username}'")  # EVAL-SINK
        return cursor.fetchall()


@router.get("/sqli/indirect")
def search_users(username: str = ""):
    rows = _find_users(username)
    return {"results": [list(row) for row in rows]}
