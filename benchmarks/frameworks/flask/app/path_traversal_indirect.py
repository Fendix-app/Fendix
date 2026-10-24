import os

from flask import jsonify, request

from app.blueprint import bp

REPORTS_DIR = "/srv/app/reports"


def _load_report(filename: str) -> str:
    with open(os.path.join(REPORTS_DIR, filename), encoding="utf-8") as fh:  # EVAL-SINK
        return fh.read()


@bp.route("/path-traversal/indirect", endpoint="path_traversal_indirect")
def read_report():
    filename = request.args.get("filename", "")
    return jsonify(content=_load_report(filename))
