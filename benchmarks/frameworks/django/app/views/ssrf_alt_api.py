import urllib.request

from django.http import JsonResponse


def fetch_url(request):
    url = request.GET.get("url", "")
    with urllib.request.urlopen(url, timeout=5) as resp:  # EVAL-SINK
        body = resp.read(500).decode("utf-8", "replace")
        status = resp.status
    return JsonResponse({"status": status, "body": body})
