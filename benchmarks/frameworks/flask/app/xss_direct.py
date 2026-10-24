from flask import make_response, request

from app.blueprint import bp


@bp.route("/xss/direct", endpoint="xss_direct")
def greet():
    name = request.args.get("name", "")
    return make_response(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK
