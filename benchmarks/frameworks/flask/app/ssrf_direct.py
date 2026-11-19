import requests
from flask import jsonify, request

from app.blueprint import bp


@bp.route("/ssrf/direct", endpoint="ssrf_direct")
def fetch_url():
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)  # EVAL-SINK
    return jsonify(status=resp.status_code, body=resp.text[:500])
