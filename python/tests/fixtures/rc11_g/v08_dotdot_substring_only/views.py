from .helpers import serve_v08_dotdot_substring_only


def view_v08_dotdot_substring_only(request):
    name = request.GET.get("name")
    return serve_v08_dotdot_substring_only(name)
