from flask import jsonify, request

from app.blueprint import bp
from app.services.url_fetcher import fetch


@bp.route("/ssrf/cross-file", endpoint="ssrf_cross_file")
def fetch_url():
    url = request.args.get("url", "")
    return jsonify(fetch(url))
