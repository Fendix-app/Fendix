import subprocess

from flask import jsonify

from app.blueprint import bp

HEALTHCHECK_HOST = "db.internal"


@bp.route("/cmdi/safe-lookalike", endpoint="cmdi_safe_lookalike")
def ping_database():
    result = subprocess.run(f"ping -c 1 {HEALTHCHECK_HOST}", shell=True, capture_output=True, text=True)  # EVAL-SAFE
    return jsonify(output=result.stdout)
