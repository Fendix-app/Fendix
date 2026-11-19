import subprocess

from django.http import JsonResponse


def ping_host(request):
    host = request.GET.get("host", "")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)  # EVAL-SINK
    return JsonResponse({"output": result.stdout})
