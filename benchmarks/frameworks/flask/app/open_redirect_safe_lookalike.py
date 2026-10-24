from flask import redirect

from app.blueprint import bp

SSO_LOGOUT_URL = "https://sso.example.com/logout"


@bp.route("/open-redirect/safe-lookalike", endpoint="open_redirect_safe_lookalike")
def sso_logout():
    return redirect(SSO_LOGOUT_URL)  # EVAL-SAFE
