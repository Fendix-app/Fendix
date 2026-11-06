from flask import redirect


def redirect_after_login(next_url: str):
    return redirect(next_url)  # EVAL-SINK
