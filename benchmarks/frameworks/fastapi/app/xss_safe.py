import html

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/xss/safe")
def greet(name: str = ""):
    return HTMLResponse(f"<h1>Hello, {html.escape(name)}!</h1>")  # EVAL-SAFE
