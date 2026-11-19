import requests


def fetch(url: str) -> dict:
    resp = requests.get(url, timeout=5)  # EVAL-SINK
    return {"status": resp.status_code, "body": resp.text[:500]}
