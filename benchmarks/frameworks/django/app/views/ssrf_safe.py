from urllib.parse import urlparse

import requests
from django.http import JsonResponse

ALLOWED_FETCH_HOSTS = {"api.example.com", "cdn.example.com"}


def fetch_url(request):
    url = request.GET.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        return JsonResponse({"error": "host not allowed"}, status=400)
    resp = requests.get(url, timeout=5)  # EVAL-SAFE
    return JsonResponse({"status": resp.status_code, "body": resp.text[:500]})
