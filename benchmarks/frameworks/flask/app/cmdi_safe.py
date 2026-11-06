import subprocess

from flask import jsonify, request

from app.blueprint import bp


@bp.route("/cmdi/safe", endpoint="cmdi_safe")
def ping_host():
    host = request.args.get("host", "")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)  # EVAL-SAFE
    return jsonify(output=result.stdout)
