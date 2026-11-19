from .helpers import serve_v10_local_safe_join


def view_v10_local_safe_join(request):
    name = request.GET.get("name")
    return serve_v10_local_safe_join(name)
