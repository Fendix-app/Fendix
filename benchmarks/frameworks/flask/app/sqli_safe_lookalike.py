import sqlite3
from contextlib import closing

from flask import jsonify

from app.blueprint import bp

DB_PATH = "app.db"
USERS_TABLE = "users"


@bp.route("/sqli/safe-lookalike", endpoint="sqli_safe_lookalike")
def list_active_users():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email FROM {USERS_TABLE} WHERE is_active = 1 ORDER BY username")  # EVAL-SAFE
        rows = cursor.fetchall()
    return jsonify(results=[list(row) for row in rows])
