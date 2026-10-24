import requests
from fastapi import APIRouter

router = APIRouter()

STATUS_API_BASE = "https://status.example.com"


@router.get("/ssrf/safe-lookalike")
def upstream_status():
    resp = requests.get(f"{STATUS_API_BASE}/api/v2/status.json", timeout=5)  # EVAL-SAFE
    return {"status": resp.status_code, "body": resp.text[:500]}
