import secrets
import sqlite3
from contextlib import closing
from typing import Annotated

from fastapi import APIRouter, Form

router = APIRouter()

DB_PATH = "app.db"


@router.post("/weak-random-token/safe", status_code=201)
def create_api_key(label: Annotated[str, Form()] = ""):
    api_key = secrets.token_urlsafe(30)  # EVAL-SAFE
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("INSERT INTO api_keys (label, token) VALUES (?, ?)", (label, api_key))
        conn.commit()
    return {"label": label, "api_key": api_key}
