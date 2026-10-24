from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/xss/direct")
def greet(name: str = ""):
    return HTMLResponse(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK
