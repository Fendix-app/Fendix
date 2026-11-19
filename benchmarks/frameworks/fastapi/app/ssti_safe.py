from fastapi import APIRouter
from jinja2 import Template

router = APIRouter()

NOTIFICATION_TEMPLATE = "Hi {{ name }}, your order has shipped."


@router.get("/ssti/safe")
def preview_notification(name: str = ""):
    rendered = Template(NOTIFICATION_TEMPLATE).render(name=name)  # EVAL-SAFE
    return {"preview": rendered}
