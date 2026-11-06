from typing import Annotated

from fastapi import APIRouter, Query

from app.services.login_redirects import redirect_after_login

router = APIRouter()


@router.get("/open-redirect/cross-file")
def login_redirect(next_url: Annotated[str, Query(alias="next")] = "/"):
    return redirect_after_login(next_url)
