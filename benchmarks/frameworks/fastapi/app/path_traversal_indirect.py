import os

from fastapi import APIRouter

router = APIRouter()

REPORTS_DIR = "/srv/app/reports"


def _load_report(filename: str) -> str:
    with open(os.path.join(REPORTS_DIR, filename), encoding="utf-8") as fh:  # EVAL-SINK
        return fh.read()


@router.get("/path-traversal/indirect")
def read_report(filename: str = ""):
    return {"content": _load_report(filename)}
