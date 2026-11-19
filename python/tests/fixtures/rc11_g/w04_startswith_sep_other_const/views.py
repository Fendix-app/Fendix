from .helpers import serve_w04_startswith_sep_other_const


def view_w04_startswith_sep_other_const(request):
    name = request.GET.get("name")
    return serve_w04_startswith_sep_other_const(name)
