import os

from django.http import JsonResponse

REPORTS_DIR = "/srv/app/reports"


def read_report(request):
    filename = request.GET.get("filename", "")
    with open(os.path.join(REPORTS_DIR, filename), encoding="utf-8") as fh:  # EVAL-SINK
        content = fh.read()
    return JsonResponse({"content": content})
