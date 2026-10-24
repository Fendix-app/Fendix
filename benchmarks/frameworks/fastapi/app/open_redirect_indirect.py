from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import RedirectResponse

router = APIRouter()


def _redirect_after_login(next_url: str):
    return RedirectResponse(next_url)  # EVAL-SINK


@router.get("/open-redirect/indirect")
def login_redirect(next_url: Annotated[str, Query(alias="next")] = "/"):
    return _redirect_after_login(next_url)
