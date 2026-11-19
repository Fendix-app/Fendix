from .helpers import serve_v09_helper_startswith_no_sep


def view_v09_helper_startswith_no_sep(request):
    name = request.GET.get("name")
    return serve_v09_helper_startswith_no_sep(name)
