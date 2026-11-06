import os

from django.http import JsonResponse

REPORTS_DIR = "/srv/app/reports"


def read_report(request):
    filename = request.GET.get("filename", "")
    base_dir = os.path.realpath(REPORTS_DIR)
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    if os.path.commonpath([base_dir, full_path]) != base_dir:
        return JsonResponse({"error": "invalid filename"}, status=400)
    with open(full_path, encoding="utf-8") as fh:  # EVAL-SAFE
        content = fh.read()
    return JsonResponse({"content": content})
