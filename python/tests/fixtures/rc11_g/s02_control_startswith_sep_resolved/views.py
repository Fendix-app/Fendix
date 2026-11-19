from .helpers import serve_s02_control_startswith_sep_resolved


def view_s02_control_startswith_sep_resolved(request):
    name = request.GET.get("name")
    return serve_s02_control_startswith_sep_resolved(name)
