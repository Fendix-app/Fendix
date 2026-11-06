from django.contrib.auth.models import User
from django.http import JsonResponse


def search_users(request):
    username = request.GET.get("username", "")
    users = User.objects.raw(f"SELECT id, username, email FROM auth_user WHERE username = '{username}'")  # EVAL-SINK
    return JsonResponse({"results": [[user.id, user.username, user.email] for user in users]})
