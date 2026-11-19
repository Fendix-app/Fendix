from fastapi import APIRouter
from jinja2 import Template

router = APIRouter()

MAINTENANCE_TEMPLATE = "{{ service }} is down for maintenance until {{ until }} UTC."
SERVICE_NAME = "Inventory Service"
MAINTENANCE_UNTIL = "02:00"


@router.get("/ssti/safe-lookalike")
def maintenance_banner():
    context = {"service": SERVICE_NAME, "until": MAINTENANCE_UNTIL}
    rendered = Template(MAINTENANCE_TEMPLATE).render(**context)  # EVAL-SAFE
    return {"banner": rendered}
