from .helpers import serve_v32_computed_parent_root


def view_v32_computed_parent_root(request):
    name = request.GET.get("name")
    return serve_v32_computed_parent_root(name)
