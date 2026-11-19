from flask import redirect, request

from app.blueprint import bp


@bp.route("/open-redirect/direct", endpoint="open_redirect_direct")
def login_redirect():
    next_url = request.args.get("next", "/")
    return redirect(next_url)  # EVAL-SINK
