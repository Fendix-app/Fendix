import requests
from django.http import JsonResponse


def _fetch(url: str) -> dict:
    resp = requests.get(url, timeout=5)  # EVAL-SINK
    return {"status": resp.status_code, "body": resp.text[:500]}


def fetch_url(request):
    url = request.GET.get("url", "")
    return JsonResponse(_fetch(url))
