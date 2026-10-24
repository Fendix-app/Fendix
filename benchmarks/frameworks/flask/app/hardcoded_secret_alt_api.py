import psycopg
from flask import jsonify

from app.blueprint import bp

REPORTING_DATABASE_URL = "postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app"  # EVAL-SINK


@bp.route("/hardcoded-secret/alt-api", endpoint="hardcoded_secret_alt_api")
def order_stats():
    with psycopg.connect(REPORTING_DATABASE_URL) as conn:
        row = conn.execute("SELECT count(*) FROM orders").fetchone()
    return jsonify(orders=row[0])
