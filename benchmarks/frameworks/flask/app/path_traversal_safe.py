import os

from flask import jsonify, request

from app.blueprint import bp

REPORTS_DIR = "/srv/app/reports"


@bp.route("/path-traversal/safe", endpoint="path_traversal_safe")
def read_report():
    filename = request.args.get("filename", "")
    base_dir = os.path.realpath(REPORTS_DIR)
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    if os.path.commonpath([base_dir, full_path]) != base_dir:
        return jsonify(error="invalid filename"), 400
    with open(full_path, encoding="utf-8") as fh:  # EVAL-SAFE
        content = fh.read()
    return jsonify(content=content)
