from .helpers import serve_fx19_dotdot_isabs_inline_ok


def view_fx19_dotdot_isabs_inline_ok(request):
    name = request.GET.get("name")
    return serve_fx19_dotdot_isabs_inline_ok(name)
