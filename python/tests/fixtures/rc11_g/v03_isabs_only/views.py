from .helpers import serve_v03_isabs_only


def view_v03_isabs_only(request):
    name = request.GET.get("name")
    return serve_v03_isabs_only(name)
