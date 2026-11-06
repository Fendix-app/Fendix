import hashlib
import sqlite3
from contextlib import closing

from flask import jsonify, request

from app.blueprint import bp

DB_PATH = "app.db"


def _hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # EVAL-SINK


@bp.route("/weak-password-hash/indirect", methods=["POST"], endpoint="weak_password_hash_indirect")
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = _hash_password(password)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    return jsonify(created=username), 201
