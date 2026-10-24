import os
from typing import Annotated

import jwt
from fastapi import APIRouter, Header, HTTPException

router = APIRouter()

JWT_SECRET = os.environ["JWT_SECRET"]


@router.get("/jwt-no-verify/safe")
def current_user(authorization: Annotated[str, Header()] = ""):
    token = authorization.removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # EVAL-SAFE
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"user_id": claims.get("sub"), "role": claims.get("role")}
