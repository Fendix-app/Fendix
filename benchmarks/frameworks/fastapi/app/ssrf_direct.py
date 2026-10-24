import requests
from fastapi import APIRouter

router = APIRouter()


@router.get("/ssrf/direct")
def fetch_url(url: str = ""):
    resp = requests.get(url, timeout=5)  # EVAL-SINK
    return {"status": resp.status_code, "body": resp.text[:500]}
