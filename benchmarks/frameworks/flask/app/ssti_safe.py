from flask import jsonify, render_template_string, request

from app.blueprint import bp

NOTIFICATION_TEMPLATE = "Hi {{ name }}, your order has shipped."


@bp.route("/ssti/safe", endpoint="ssti_safe")
def preview_notification():
    name = request.args.get("name", "")
    rendered = render_template_string(NOTIFICATION_TEMPLATE, name=name)  # EVAL-SAFE
    return jsonify(preview=rendered)
