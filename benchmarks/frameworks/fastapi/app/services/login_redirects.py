from fastapi.responses import RedirectResponse


def redirect_after_login(next_url: str):
    return RedirectResponse(next_url)  # EVAL-SINK
