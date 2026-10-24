import requests
from flask import jsonify

from app.blueprint import bp

STATUS_API_BASE = "https://status.example.com"


@bp.route("/ssrf/safe-lookalike", endpoint="ssrf_safe_lookalike")
def upstream_status():
    resp = requests.get(f"{STATUS_API_BASE}/api/v2/status.json", timeout=5)  # EVAL-SAFE
    return jsonify(status=resp.status_code, body=resp.text[:500])
