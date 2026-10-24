import requests
from django.http import JsonResponse

STATUS_API_BASE = "https://status.example.com"


def upstream_status(request):
    resp = requests.get(f"{STATUS_API_BASE}/api/v2/status.json", timeout=5)  # EVAL-SAFE
    return JsonResponse({"status": resp.status_code, "body": resp.text[:500]})
