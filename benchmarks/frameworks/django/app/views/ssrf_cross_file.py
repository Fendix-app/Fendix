from django.http import JsonResponse

from app.services.url_fetcher import fetch


def fetch_url(request):
    url = request.GET.get("url", "")
    return JsonResponse(fetch(url))
