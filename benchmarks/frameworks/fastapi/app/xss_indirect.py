from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


def _render_greeting(name: str):
    return HTMLResponse(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK


@router.get("/xss/indirect")
def greet(name: str = ""):
    return _render_greeting(name)
