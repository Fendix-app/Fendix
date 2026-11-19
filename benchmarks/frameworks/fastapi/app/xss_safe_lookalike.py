from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

SERVICE_NAME = "Inventory Service"


@router.get("/xss/safe-lookalike")
def about_page():
    return HTMLResponse(f"<h1>{SERVICE_NAME}</h1><p>All systems operational.</p>")  # EVAL-SAFE
