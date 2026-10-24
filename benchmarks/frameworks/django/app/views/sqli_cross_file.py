from django.http import JsonResponse

from app.services.user_queries import find_users


def search_users(request):
    username = request.GET.get("username", "")
    rows = find_users(username)
    return JsonResponse({"results": [list(row) for row in rows]})
