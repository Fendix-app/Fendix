from fastapi import APIRouter
from sqlalchemy import create_engine, text

router = APIRouter()

engine = create_engine("sqlite:///app.db")


@router.get("/sqli/alt-api")
def search_users(username: str = ""):
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT id, username, email FROM users WHERE username = '{username}'"))  # EVAL-SINK
        rows = result.fetchall()
    return {"results": [list(row) for row in rows]}
