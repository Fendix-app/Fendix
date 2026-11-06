import os

from fastapi import APIRouter

router = APIRouter()

REPORTS_DIR = "/srv/app/reports"


@router.get("/path-traversal/direct")
def read_report(filename: str = ""):
    with open(os.path.join(REPORTS_DIR, filename), encoding="utf-8") as fh:  # EVAL-SINK
        content = fh.read()
    return {"content": content}
