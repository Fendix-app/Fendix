import sqlite3
from contextlib import closing
from typing import Annotated

import bcrypt
from fastapi import APIRouter, Form

router = APIRouter()

DB_PATH = "app.db"


@router.post("/weak-password-hash/safe", status_code=201)
def register(username: Annotated[str, Form()], password: Annotated[str, Form()]):
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # EVAL-SAFE
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    return {"created": username}
