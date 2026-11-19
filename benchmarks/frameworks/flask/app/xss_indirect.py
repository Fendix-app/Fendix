from flask import make_response, request

from app.blueprint import bp


def _render_greeting(name: str):
    return make_response(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK


@bp.route("/xss/indirect", endpoint="xss_indirect")
def greet():
    name = request.args.get("name", "")
    return _render_greeting(name)
