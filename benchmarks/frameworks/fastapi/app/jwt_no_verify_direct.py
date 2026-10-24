from typing import Annotated

import jwt
from fastapi import APIRouter, Header, HTTPException

router = APIRouter()


@router.get("/jwt-no-verify/direct")
def current_user(authorization: Annotated[str, Header()] = ""):
    token = authorization.removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, options={"verify_signature": False})  # EVAL-SINK
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"user_id": claims.get("sub"), "role": claims.get("role")}
