import subprocess

from fastapi import APIRouter

router = APIRouter()


@router.get("/cmdi/direct")
def ping_host(host: str = ""):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # EVAL-SINK
    return {"output": result.stdout}
