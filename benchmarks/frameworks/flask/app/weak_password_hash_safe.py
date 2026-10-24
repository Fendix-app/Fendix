import sqlite3
from contextlib import closing

from flask import jsonify, request
from werkzeug.security import generate_password_hash

from app.blueprint import bp

DB_PATH = "app.db"


@bp.route("/weak-password-hash/safe", methods=["POST"], endpoint="weak_password_hash_safe")
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = generate_password_hash(password)  # EVAL-SAFE
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    return jsonify(created=username), 201
