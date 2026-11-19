from .helpers import serve_v17_prefix_slash_dotdot_only


def view_v17_prefix_slash_dotdot_only(request):
    name = request.GET.get("name")
    return serve_v17_prefix_slash_dotdot_only(name)
