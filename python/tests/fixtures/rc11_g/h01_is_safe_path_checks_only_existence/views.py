from .helpers import serve_h01_is_safe_path_checks_only_existence


def view_h01_is_safe_path_checks_only_existence(request):
    name = request.GET.get("name")
    return serve_h01_is_safe_path_checks_only_existence(name)
