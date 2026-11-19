from .helpers import serve_v34_enclosing_if_or


def view_v34_enclosing_if_or(request):
    name = request.GET.get("name")
    return serve_v34_enclosing_if_or(name)
