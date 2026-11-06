import os

from django.http import JsonResponse


def ping_host(request):
    host = request.GET.get("host", "")
    exit_code = os.system(f"ping -c 1 {host}")  # EVAL-SINK
    return JsonResponse({"reachable": exit_code == 0})
