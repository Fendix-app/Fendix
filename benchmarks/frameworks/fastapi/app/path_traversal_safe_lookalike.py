import os

from fastapi import APIRouter

router = APIRouter()

REPORTS_DIR = "/srv/app/reports"
LATEST_REPORT = "latest.txt"


@router.get("/path-traversal/safe-lookalike")
def latest_report():
    with open(os.path.join(REPORTS_DIR, LATEST_REPORT), encoding="utf-8") as fh:  # EVAL-SAFE
        content = fh.read()
    return {"content": content}
