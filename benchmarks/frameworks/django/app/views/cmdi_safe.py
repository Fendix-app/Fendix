import subprocess

from django.http import JsonResponse


def ping_host(request):
    host = request.GET.get("host", "")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)  # EVAL-SAFE
    return JsonResponse({"output": result.stdout})
