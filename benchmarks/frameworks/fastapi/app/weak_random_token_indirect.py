import random
import sqlite3
import string
from contextlib import closing
from typing import Annotated

from fastapi import APIRouter, Form

router = APIRouter()

DB_PATH = "app.db"
TOKEN_ALPHABET = string.ascii_letters + string.digits


def _generate_api_key() -> str:
    return "".join(random.choices(TOKEN_ALPHABET, k=40))  # EVAL-SINK


@router.post("/weak-random-token/indirect", status_code=201)
def create_api_key(label: Annotated[str, Form()] = ""):
    api_key = _generate_api_key()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("INSERT INTO api_keys (label, token) VALUES (?, ?)", (label, api_key))
        conn.commit()
    return {"label": label, "api_key": api_key}
