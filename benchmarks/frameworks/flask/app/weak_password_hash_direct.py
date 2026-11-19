import hashlib
import sqlite3
from contextlib import closing

from flask import jsonify, request

from app.blueprint import bp

DB_PATH = "app.db"


@bp.route("/weak-password-hash/direct", methods=["POST"], endpoint="weak_password_hash_direct")
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = hashlib.md5(password.encode()).hexdigest()  # EVAL-SINK
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    return jsonify(created=username), 201
