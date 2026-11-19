from typing import Annotated

from fastapi import APIRouter, Query
from jinja2 import Template

router = APIRouter()


def _render_preview(template_src: str, name: str) -> str:
    return Template(template_src).render(name=name)  # EVAL-SINK


@router.get("/ssti/indirect")
def preview_notification(template_src: Annotated[str, Query(alias="template")] = "", name: str = ""):
    return {"preview": _render_preview(template_src, name)}
