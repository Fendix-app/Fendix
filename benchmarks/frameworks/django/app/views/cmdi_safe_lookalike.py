import subprocess

from django.http import JsonResponse

HEALTHCHECK_HOST = "db.internal"


def ping_database(request):
    result = subprocess.run(f"ping -c 1 {HEALTHCHECK_HOST}", shell=True, capture_output=True, text=True)  # EVAL-SAFE
    return JsonResponse({"output": result.stdout})
