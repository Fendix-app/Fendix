from .helpers import serve_fx42_django_safe_join_ok


def view_fx42_django_safe_join_ok(request):
    name = request.GET.get("name")
    return serve_fx42_django_safe_join_ok(name)
