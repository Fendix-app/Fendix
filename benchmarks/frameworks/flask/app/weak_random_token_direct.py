import random
import sqlite3
import string
from contextlib import closing

from flask import jsonify, request

from app.blueprint import bp

DB_PATH = "app.db"
TOKEN_ALPHABET = string.ascii_letters + string.digits


@bp.route("/weak-random-token/direct", methods=["POST"], endpoint="weak_random_token_direct")
def create_api_key():
    label = request.form.get("label", "")
    api_key = "".join(random.choices(TOKEN_ALPHABET, k=40))  # EVAL-SINK
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("INSERT INTO api_keys (label, token) VALUES (?, ?)", (label, api_key))
        conn.commit()
    return jsonify(label=label, api_key=api_key), 201
