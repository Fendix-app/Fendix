import subprocess

from flask import jsonify, request

from app.blueprint import bp


def _ping(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # EVAL-SINK
    return result.stdout


@bp.route("/cmdi/indirect", endpoint="cmdi_indirect")
def ping_host():
    host = request.args.get("host", "")
    return jsonify(output=_ping(host))
