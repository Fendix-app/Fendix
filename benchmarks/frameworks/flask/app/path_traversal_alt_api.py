import os

from flask import request, send_file

from app.blueprint import bp

REPORTS_DIR = "/srv/app/reports"


@bp.route("/path-traversal/alt-api", endpoint="path_traversal_alt_api")
def download_report():
    filename = request.args.get("filename", "")
    return send_file(os.path.join(REPORTS_DIR, filename), as_attachment=True)  # EVAL-SINK
