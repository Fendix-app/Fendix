import requests
from flask import jsonify

from app.blueprint import bp

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


@bp.route("/hardcoded-secret/indirect", endpoint="hardcoded_secret_indirect")
def list_repos():
    return jsonify(repos=[repo["full_name"] for repo in _github_repos()])
