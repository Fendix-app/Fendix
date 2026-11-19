from .helpers import serve_fx01c_inline_startswith_sep_ok


def view_fx01c_inline_startswith_sep_ok(request):
    name = request.GET.get("name")
    return serve_fx01c_inline_startswith_sep_ok(name)
