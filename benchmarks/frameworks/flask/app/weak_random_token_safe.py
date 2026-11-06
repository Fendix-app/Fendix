import secrets
import sqlite3
from contextlib import closing

from flask import jsonify, request

from app.blueprint import bp

DB_PATH = "app.db"


@bp.route("/weak-random-token/safe", methods=["POST"], endpoint="weak_random_token_safe")
def create_api_key():
    label = request.form.get("label", "")
    api_key = secrets.token_urlsafe(30)  # EVAL-SAFE
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("INSERT INTO api_keys (label, token) VALUES (?, ?)", (label, api_key))
        conn.commit()
    return jsonify(label=label, api_key=api_key), 201
