import subprocess

from django.http import JsonResponse


def _ping(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # EVAL-SINK
    return result.stdout


def ping_host(request):
    host = request.GET.get("host", "")
    return JsonResponse({"output": _ping(host)})
