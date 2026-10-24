from flask import jsonify, render_template_string, request

from app.blueprint import bp


@bp.route("/ssti/direct", endpoint="ssti_direct")
def preview_notification():
    template_src = request.args.get("template", "")
    name = request.args.get("name", "")
    rendered = render_template_string(template_src, name=name)  # EVAL-SINK
    return jsonify(preview=rendered)
