from fastapi import APIRouter

from app.services.greeting_pages import render_greeting

router = APIRouter()


@router.get("/xss/cross-file")
def greet(name: str = ""):
    return render_greeting(name)
