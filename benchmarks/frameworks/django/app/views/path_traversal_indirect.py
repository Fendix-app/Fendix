import os

from django.http import JsonResponse

REPORTS_DIR = "/srv/app/reports"


def _load_report(filename: str) -> str:
    with open(os.path.join(REPORTS_DIR, filename), encoding="utf-8") as fh:  # EVAL-SINK
        return fh.read()


def read_report(request):
    filename = request.GET.get("filename", "")
    return JsonResponse({"content": _load_report(filename)})
