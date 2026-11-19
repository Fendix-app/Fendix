from .helpers import serve_fx10b_startswith_no_sep_inline


def view_fx10b_startswith_no_sep_inline(request):
    name = request.GET.get("name")
    return serve_fx10b_startswith_no_sep_inline(name)
