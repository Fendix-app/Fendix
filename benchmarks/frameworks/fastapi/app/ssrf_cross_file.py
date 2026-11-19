from fastapi import APIRouter

from app.services.url_fetcher import fetch

router = APIRouter()


@router.get("/ssrf/cross-file")
def fetch_url(url: str = ""):
    return fetch(url)
