from flask import request

from app.blueprint import bp
from app.services.greeting_pages import render_greeting


@bp.route("/xss/cross-file", endpoint="xss_cross_file")
def greet():
    name = request.args.get("name", "")
    return render_greeting(name)
