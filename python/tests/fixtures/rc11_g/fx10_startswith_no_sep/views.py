from .helpers import serve_fx10_startswith_no_sep


def view_fx10_startswith_no_sep(request):
    name = request.GET.get("name")
    return serve_fx10_startswith_no_sep(name)
