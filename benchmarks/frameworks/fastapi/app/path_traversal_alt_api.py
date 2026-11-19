import os

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

REPORTS_DIR = "/srv/app/reports"


@router.get("/path-traversal/alt-api")
def download_report(filename: str = ""):
    return FileResponse(os.path.join(REPORTS_DIR, filename))  # EVAL-SINK
