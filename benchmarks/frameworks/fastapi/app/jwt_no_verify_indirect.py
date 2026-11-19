from typing import Annotated

import jwt
from fastapi import APIRouter, Header, HTTPException

router = APIRouter()


def _decode_token(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})  # EVAL-SINK


@router.get("/jwt-no-verify/indirect")
def current_user(authorization: Annotated[str, Header()] = ""):
    token = authorization.removeprefix("Bearer ")
    try:
        claims = _decode_token(token)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"user_id": claims.get("sub"), "role": claims.get("role")}
