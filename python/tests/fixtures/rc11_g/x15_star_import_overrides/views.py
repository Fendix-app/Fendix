from .helpers import serve_x15_star_import_overrides


def view_x15_star_import_overrides(request):
    name = request.GET.get("name")
    return serve_x15_star_import_overrides(name)
