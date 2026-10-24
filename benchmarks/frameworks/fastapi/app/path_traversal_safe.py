import os

from fastapi import APIRouter, HTTPException

router = APIRouter()

REPORTS_DIR = "/srv/app/reports"


@router.get("/path-traversal/safe")
def read_report(filename: str = ""):
    base_dir = os.path.realpath(REPORTS_DIR)
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    if os.path.commonpath([base_dir, full_path]) != base_dir:
        raise HTTPException(status_code=400, detail="invalid filename")
    with open(full_path, encoding="utf-8") as fh:  # EVAL-SAFE
        content = fh.read()
    return {"content": content}
