from flask import jsonify, request
from sqlalchemy import create_engine, text

from app.blueprint import bp

engine = create_engine("sqlite:///app.db")


@bp.route("/sqli/alt-api", endpoint="sqli_alt_api")
def search_users():
    username = request.args.get("username", "")
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT id, username, email FROM users WHERE username = '{username}'"))  # EVAL-SINK
        rows = result.fetchall()
    return jsonify(results=[list(row) for row in rows])
