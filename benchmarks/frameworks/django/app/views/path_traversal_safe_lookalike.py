import os

from django.http import JsonResponse

REPORTS_DIR = "/srv/app/reports"
LATEST_REPORT = "latest.txt"


def latest_report(request):
    with open(os.path.join(REPORTS_DIR, LATEST_REPORT), encoding="utf-8") as fh:  # EVAL-SAFE
        content = fh.read()
    return JsonResponse({"content": content})
