from .helpers import serve_h14_helper_requires_abspath_only


def view_h14_helper_requires_abspath_only(request):
    name = request.GET.get("name")
    return serve_h14_helper_requires_abspath_only(name)
