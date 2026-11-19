import urllib.request

from flask import jsonify, request

from app.blueprint import bp


@bp.route("/ssrf/alt-api", endpoint="ssrf_alt_api")
def fetch_url():
    url = request.args.get("url", "")
    with urllib.request.urlopen(url, timeout=5) as resp:  # EVAL-SINK
        body = resp.read(500).decode("utf-8", "replace")
        status = resp.status
    return jsonify(status=status, body=body)
