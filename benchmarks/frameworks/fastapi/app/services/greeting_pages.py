from fastapi.responses import HTMLResponse


def render_greeting(name: str):
    return HTMLResponse(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK
