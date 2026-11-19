from .helpers import serve_v18_lstrip_slash_only


def view_v18_lstrip_slash_only(request):
    name = request.GET.get("name")
    return serve_v18_lstrip_slash_only(name)
