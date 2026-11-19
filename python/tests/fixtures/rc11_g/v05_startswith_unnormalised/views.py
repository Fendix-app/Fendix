from .helpers import serve_v05_startswith_unnormalised


def view_v05_startswith_unnormalised(request):
    name = request.GET.get("name")
    return serve_v05_startswith_unnormalised(name)
