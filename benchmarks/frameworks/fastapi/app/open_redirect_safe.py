from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Query
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/open-redirect/safe")
def login_redirect(next_url: Annotated[str, Query(alias="next")] = "/"):
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc or not next_url.startswith("/") or "\\" in next_url:
        next_url = "/"
    return RedirectResponse(next_url)  # EVAL-SAFE
