from flask import render_template, request
from markupsafe import Markup

from app.blueprint import bp


@bp.route("/xss/alt-api", endpoint="xss_alt_api")
def greet():
    name = request.args.get("name", "")
    return render_template("greeting.html", name=Markup(name))  # EVAL-SINK
