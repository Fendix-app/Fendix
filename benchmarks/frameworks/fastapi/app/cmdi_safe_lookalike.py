import subprocess

from fastapi import APIRouter

router = APIRouter()

HEALTHCHECK_HOST = "db.internal"


@router.get("/cmdi/safe-lookalike")
def ping_database():
    result = subprocess.run(f"ping -c 1 {HEALTHCHECK_HOST}", shell=True, capture_output=True, text=True)  # EVAL-SAFE
    return {"output": result.stdout}
