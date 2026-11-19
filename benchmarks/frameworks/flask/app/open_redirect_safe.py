from urllib.parse import urlparse

from flask import redirect, request

from app.blueprint import bp


@bp.route("/open-redirect/safe", endpoint="open_redirect_safe")
def login_redirect():
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc or not next_url.startswith("/") or "\\" in next_url:
        next_url = "/"
    return redirect(next_url)  # EVAL-SAFE
