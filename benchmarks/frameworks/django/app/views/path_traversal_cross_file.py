from django.http import JsonResponse

from app.services.report_store import load_report


def read_report(request):
    filename = request.GET.get("filename", "")
    return JsonResponse({"content": load_report(filename)})
