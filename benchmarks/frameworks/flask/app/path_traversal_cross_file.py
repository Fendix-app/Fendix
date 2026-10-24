from flask import jsonify, request

from app.blueprint import bp
from app.services.report_store import load_report


@bp.route("/path-traversal/cross-file", endpoint="path_traversal_cross_file")
def read_report():
    filename = request.args.get("filename", "")
    return jsonify(content=load_report(filename))
