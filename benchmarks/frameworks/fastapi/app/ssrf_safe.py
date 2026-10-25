from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException

router = APIRouter()

ALLOWED_FETCH_HOSTS = {"api.example.com", "cdn.example.com"}


@router.get("/ssrf/safe")
def fetch_url(url: str = ""):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc not in ALLOWED_FETCH_HOSTS:
        raise HTTPException(status_code=400, detail="host not allowed")
    resp = requests.get(url, timeout=5)  # EVAL-SAFE
    return {"status": resp.status_code, "body": resp.text[:500]}
