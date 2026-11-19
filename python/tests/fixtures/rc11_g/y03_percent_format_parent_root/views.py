from .helpers import serve_y03_percent_format_parent_root


def view_y03_percent_format_parent_root(request):
    name = request.GET.get("name")
    return serve_y03_percent_format_parent_root(name)
