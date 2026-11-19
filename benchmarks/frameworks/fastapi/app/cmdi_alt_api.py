import os

from fastapi import APIRouter

router = APIRouter()


@router.get("/cmdi/alt-api")
def ping_host(host: str = ""):
    exit_code = os.system(f"ping -c 1 {host}")  # EVAL-SINK
    return {"reachable": exit_code == 0}
