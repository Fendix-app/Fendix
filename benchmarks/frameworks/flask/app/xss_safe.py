from flask import make_response, request
from markupsafe import escape

from app.blueprint import bp


@bp.route("/xss/safe", endpoint="xss_safe")
def greet():
    name = request.args.get("name", "")
    return make_response(f"<h1>Hello, {escape(name)}!</h1>")  # EVAL-SAFE
