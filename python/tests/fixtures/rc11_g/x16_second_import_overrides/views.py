from .helpers import serve_x16_second_import_overrides


def view_x16_second_import_overrides(request):
    name = request.GET.get("name")
    return serve_x16_second_import_overrides(name)
