from urllib.parse import urlparse

import requests
from flask import jsonify, request

from app.blueprint import bp

ALLOWED_FETCH_HOSTS = {"api.example.com", "cdn.example.com"}


@bp.route("/ssrf/safe", endpoint="ssrf_safe")
def fetch_url():
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        return jsonify(error="host not allowed"), 400
    resp = requests.get(url, timeout=5)  # EVAL-SAFE
    return jsonify(status=resp.status_code, body=resp.text[:500])
