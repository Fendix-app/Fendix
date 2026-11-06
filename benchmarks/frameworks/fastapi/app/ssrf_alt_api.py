import urllib.request

from fastapi import APIRouter

router = APIRouter()


@router.get("/ssrf/alt-api")
def fetch_url(url: str = ""):
    with urllib.request.urlopen(url, timeout=5) as resp:  # EVAL-SINK
        body = resp.read(500).decode("utf-8", "replace")
        status = resp.status
    return {"status": status, "body": body}
