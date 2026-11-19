import subprocess

from fastapi import APIRouter

router = APIRouter()


def _ping(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # EVAL-SINK
    return result.stdout


@router.get("/cmdi/indirect")
def ping_host(host: str = ""):
    return {"output": _ping(host)}
