import subprocess

from fastapi import APIRouter

router = APIRouter()


@router.get("/cmdi/safe")
def ping_host(host: str = ""):
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)  # EVAL-SAFE
    return {"output": result.stdout}
