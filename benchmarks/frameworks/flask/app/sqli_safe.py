import sqlite3
from contextlib import closing

from flask import jsonify, request

from app.blueprint import bp

DB_PATH = "app.db"


@bp.route("/sqli/safe", endpoint="sqli_safe")
def search_users():
    username = request.args.get("username", "")
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))  # EVAL-SAFE
        rows = cursor.fetchall()
    return jsonify(results=[list(row) for row in rows])
