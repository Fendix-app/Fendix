from flask import jsonify, render_template_string

from app.blueprint import bp

MAINTENANCE_TEMPLATE = "{{ service }} is down for maintenance until {{ until }} UTC."
SERVICE_NAME = "Inventory Service"
MAINTENANCE_UNTIL = "02:00"


@bp.route("/ssti/safe-lookalike", endpoint="ssti_safe_lookalike")
def maintenance_banner():
    context = {"service": SERVICE_NAME, "until": MAINTENANCE_UNTIL}
    rendered = render_template_string(MAINTENANCE_TEMPLATE, **context)  # EVAL-SAFE
    return jsonify(banner=rendered)
