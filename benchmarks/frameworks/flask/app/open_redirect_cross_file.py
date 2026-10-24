from flask import request

from app.blueprint import bp
from app.services.login_redirects import redirect_after_login


@bp.route("/open-redirect/cross-file", endpoint="open_redirect_cross_file")
def login_redirect():
    next_url = request.args.get("next", "/")
    return redirect_after_login(next_url)
