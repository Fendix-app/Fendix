import requests
from django.http import JsonResponse


def fetch_url(request):
    url = request.GET.get("url", "")
    resp = requests.get(url, timeout=5)  # EVAL-SINK
    return JsonResponse({"status": resp.status_code, "body": resp.text[:500]})
