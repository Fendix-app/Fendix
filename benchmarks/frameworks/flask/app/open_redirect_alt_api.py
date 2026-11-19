from flask import Response, request

from app.blueprint import bp


@bp.route("/open-redirect/alt-api", endpoint="open_redirect_alt_api")
def login_redirect():
    next_url = request.args.get("next", "/")
    return Response(status=302, headers={"Location": next_url})  # EVAL-SINK
