import requests
from fastapi import APIRouter

router = APIRouter()

GITHUB_CONFIG = {
    "repos_url": "https://api.github.com/user/repos",
    "token": "__EVAL_GITHUB_TOKEN__",  # EVAL-SINK
}


def _github_repos() -> list:
    headers = {
        "Authorization": f"Bearer {GITHUB_CONFIG['token']}",
        "Accept": "application/vnd.github+json",
    }
    resp = requests.get(GITHUB_CONFIG["repos_url"], headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


@router.get("/hardcoded-secret/indirect")
def list_repos():
    return {"repos": [repo["full_name"] for repo in _github_repos()]}
