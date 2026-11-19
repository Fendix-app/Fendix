from .helpers import serve_fx21_replace_dotdot_slash


def view_fx21_replace_dotdot_slash(request):
    name = request.GET.get("name")
    return serve_fx21_replace_dotdot_slash(name)
