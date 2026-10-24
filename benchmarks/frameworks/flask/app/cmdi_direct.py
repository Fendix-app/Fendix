import subprocess

from flask import jsonify, request

from app.blueprint import bp


@bp.route("/cmdi/direct", endpoint="cmdi_direct")
def ping_host():
    host = request.args.get("host", "")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # EVAL-SINK
    return jsonify(output=result.stdout)
