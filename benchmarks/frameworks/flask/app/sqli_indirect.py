import sqlite3
from contextlib import closing

from flask import jsonify, request

from app.blueprint import bp

DB_PATH = "app.db"


def _find_users(username: str) -> list:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT id, username, email FROM users WHERE username = '{username}'")  # EVAL-SINK
        return cursor.fetchall()


@bp.route("/sqli/indirect", endpoint="sqli_indirect")
def search_users():
    username = request.args.get("username", "")
    rows = _find_users(username)
    return jsonify(results=[list(row) for row in rows])
