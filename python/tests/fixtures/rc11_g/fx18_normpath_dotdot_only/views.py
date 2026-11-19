from .helpers import serve_fx18_normpath_dotdot_only


def view_fx18_normpath_dotdot_only(request):
    name = request.GET.get("name")
    return serve_fx18_normpath_dotdot_only(name)
