from flask import jsonify, request

from app.blueprint import bp
from app.services.user_queries import find_users


@bp.route("/sqli/cross-file", endpoint="sqli_cross_file")
def search_users():
    username = request.args.get("username", "")
    rows = find_users(username)
    return jsonify(results=[list(row) for row in rows])
