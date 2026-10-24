from django.http import HttpResponse

SERVICE_NAME = "Inventory Service"


def about_page(request):
    return HttpResponse(f"<h1>{SERVICE_NAME}</h1><p>All systems operational.</p>")  # EVAL-SAFE
