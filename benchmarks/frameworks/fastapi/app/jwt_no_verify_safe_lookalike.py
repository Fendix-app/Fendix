import os
from typing import Annotated

import jwt
from fastapi import APIRouter, Header, HTTPException

router = APIRouter()

SIGNING_KEYS = {
    "primary": os.environ.get("JWT_PRIMARY_KEY", ""),
    "previous": os.environ.get("JWT_PREVIOUS_KEY", ""),
}


@router.get("/jwt-no-verify/safe-lookalike")
def current_user(authorization: Annotated[str, Header()] = ""):
    token = authorization.removeprefix("Bearer ")
    try:
        kid = jwt.get_unverified_header(token).get("kid", "")  # EVAL-SAFE
        claims = jwt.decode(token, SIGNING_KEYS[kid], algorithms=["HS256"])
    except (jwt.InvalidTokenError, KeyError):
        raise HTTPException(status_code=401, detail="invalid token")
    return {"user_id": claims.get("sub"), "role": claims.get("role")}
