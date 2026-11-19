import requests
from fastapi import APIRouter

router = APIRouter()


def _fetch(url: str) -> dict:
    resp = requests.get(url, timeout=5)  # EVAL-SINK
    return {"status": resp.status_code, "body": resp.text[:500]}


@router.get("/ssrf/indirect")
def fetch_url(url: str = ""):
    return _fetch(url)
