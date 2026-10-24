from typing import Annotated

from fastapi import APIRouter, Query, Response

router = APIRouter()


@router.get("/open-redirect/alt-api")
def login_redirect(next_url: Annotated[str, Query(alias="next")] = "/"):
    return Response(status_code=302, headers={"Location": next_url})  # EVAL-SINK
