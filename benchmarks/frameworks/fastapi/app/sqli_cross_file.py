from fastapi import APIRouter

from app.services.user_queries import find_users

router = APIRouter()


@router.get("/sqli/cross-file")
def search_users(username: str = ""):
    rows = find_users(username)
    return {"results": [list(row) for row in rows]}
