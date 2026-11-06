from fastapi import APIRouter

from app.services.network_tools import ping

router = APIRouter()


@router.get("/cmdi/cross-file")
def ping_host(host: str = ""):
    return {"output": ping(host)}
