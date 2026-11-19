import os

from flask import jsonify, request

from app.blueprint import bp

REPORTS_DIR = "/srv/app/reports"


@bp.route("/path-traversal/direct", endpoint="path_traversal_direct")
def read_report():
    filename = request.args.get("filename", "")
    with open(os.path.join(REPORTS_DIR, filename), encoding="utf-8") as fh:  # EVAL-SINK
        content = fh.read()
    return jsonify(content=content)
