from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/open-redirect/direct")
def login_redirect(next_url: Annotated[str, Query(alias="next")] = "/"):
    return RedirectResponse(next_url)  # EVAL-SINK
