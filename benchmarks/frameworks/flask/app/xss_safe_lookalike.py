from flask import make_response

from app.blueprint import bp

SERVICE_NAME = "Inventory Service"


@bp.route("/xss/safe-lookalike", endpoint="xss_safe_lookalike")
def about_page():
    return make_response(f"<h1>{SERVICE_NAME}</h1><p>All systems operational.</p>")  # EVAL-SAFE
