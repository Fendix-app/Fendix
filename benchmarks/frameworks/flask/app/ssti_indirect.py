from flask import jsonify, render_template_string, request

from app.blueprint import bp


def _render_preview(template_src: str, name: str) -> str:
    return render_template_string(template_src, name=name)  # EVAL-SINK


@bp.route("/ssti/indirect", endpoint="ssti_indirect")
def preview_notification():
    template_src = request.args.get("template", "")
    name = request.args.get("name", "")
    return jsonify(preview=_render_preview(template_src, name))
