import os

from django.http import FileResponse

REPORTS_DIR = "/srv/app/reports"


def download_report(request):
    filename = request.GET.get("filename", "")
    return FileResponse(open(os.path.join(REPORTS_DIR, filename), "rb"), as_attachment=True)  # EVAL-SINK
