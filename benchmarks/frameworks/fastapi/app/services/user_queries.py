import sqlite3
from contextlib import closing

DB_PATH = "app.db"


def find_users(username: str) -> list:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email FROM users WHERE username = '{username}'")  # EVAL-SINK
        return cursor.fetchall()
