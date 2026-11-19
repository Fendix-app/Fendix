from django.http import JsonResponse

from app.services.network_tools import ping


def ping_host(request):
    host = request.GET.get("host", "")
    return JsonResponse({"output": ping(host)})
