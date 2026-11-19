from .helpers import serve_h11_raising_helper_swallowed_by_broad_except


def view_h11_raising_helper_swallowed_by_broad_except(request):
    name = request.GET.get("name")
    return serve_h11_raising_helper_swallowed_by_broad_except(name)
