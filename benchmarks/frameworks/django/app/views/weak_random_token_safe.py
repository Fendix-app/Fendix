import secrets

from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def create_api_key(request):
    label = request.POST.get("label", "")
    api_key = secrets.token_urlsafe(30)  # EVAL-SAFE
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO api_keys (label, token) VALUES (%s, %s)", [label, api_key])
    return JsonResponse({"label": label, "api_key": api_key}, status=201)
