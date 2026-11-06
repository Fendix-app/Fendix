import os

from flask import jsonify

from app.blueprint import bp

REPORTS_DIR = "/srv/app/reports"
LATEST_REPORT = "latest.txt"


@bp.route("/path-traversal/safe-lookalike", endpoint="path_traversal_safe_lookalike")
def latest_report():
    with open(os.path.join(REPORTS_DIR, LATEST_REPORT), encoding="utf-8") as fh:  # EVAL-SAFE
        content = fh.read()
    return jsonify(content=content)
