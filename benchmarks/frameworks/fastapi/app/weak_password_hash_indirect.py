import hashlib
import sqlite3
from contextlib import closing
from typing import Annotated

from fastapi import APIRouter, Form

router = APIRouter()

DB_PATH = "app.db"


def _hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # EVAL-SINK


@router.post("/weak-password-hash/indirect", status_code=201)
def register(username: Annotated[str, Form()], password: Annotated[str, Form()]):
    password_hash = _hash_password(password)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    return {"created": username}
