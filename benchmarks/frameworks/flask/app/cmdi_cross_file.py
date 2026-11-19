from flask import jsonify, request

from app.blueprint import bp
from app.services.network_tools import ping


@bp.route("/cmdi/cross-file", endpoint="cmdi_cross_file")
def ping_host():
    host = request.args.get("host", "")
    return jsonify(output=ping(host))
