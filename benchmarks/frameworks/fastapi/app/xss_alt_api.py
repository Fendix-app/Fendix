from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


@router.get("/xss/alt-api")
def greet(request: Request, name: str = ""):
    return templates.TemplateResponse(request, "greeting.html", {"name": Markup(name)})  # EVAL-SINK
