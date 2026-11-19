from flask import redirect, request

from app.blueprint import bp


def _redirect_after_login(next_url: str):
    return redirect(next_url)  # EVAL-SINK


@bp.route("/open-redirect/indirect", endpoint="open_redirect_indirect")
def login_redirect():
    next_url = request.args.get("next", "/")
    return _redirect_after_login(next_url)
