import requests
from flask import jsonify, request

from app.blueprint import bp


def _fetch(url: str) -> dict:
    resp = requests.get(url, timeout=5)  # EVAL-SINK
    return {"status": resp.status_code, "body": resp.text[:500]}


@bp.route("/ssrf/indirect", endpoint="ssrf_indirect")
def fetch_url():
    url = request.args.get("url", "")
    return jsonify(_fetch(url))
