from fastapi import APIRouter

from app.services.report_store import load_report

router = APIRouter()


@router.get("/path-traversal/cross-file")
def read_report(filename: str = ""):
    return {"content": load_report(filename)}
