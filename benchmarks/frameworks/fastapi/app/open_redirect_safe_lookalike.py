from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()

SSO_LOGOUT_URL = "https://sso.example.com/logout"


@router.get("/open-redirect/safe-lookalike")
def sso_logout():
    return RedirectResponse(SSO_LOGOUT_URL)  # EVAL-SAFE
