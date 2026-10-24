from typing import Annotated

from fastapi import APIRouter, Query
from jinja2 import Template

router = APIRouter()


@router.get("/ssti/direct")
def preview_notification(template_src: Annotated[str, Query(alias="template")] = "", name: str = ""):
    rendered = Template(template_src).render(name=name)  # EVAL-SINK
    return {"preview": rendered}
