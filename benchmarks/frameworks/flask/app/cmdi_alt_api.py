import os

from flask import jsonify, request

from app.blueprint import bp


@bp.route("/cmdi/alt-api", endpoint="cmdi_alt_api")
def ping_host():
    host = request.args.get("host", "")
    exit_code = os.system(f"ping -c 1 {host}")  # EVAL-SINK
    return jsonify(reachable=exit_code == 0)
