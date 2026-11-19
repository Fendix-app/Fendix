from .helpers import serve_v27_or_bypass


def view_v27_or_bypass(request):
    name = request.GET.get("name")
    return serve_v27_or_bypass(name)
