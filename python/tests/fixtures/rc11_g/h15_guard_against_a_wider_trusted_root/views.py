from .helpers import serve_h15_guard_against_a_wider_trusted_root


def view_h15_guard_against_a_wider_trusted_root(request):
    name = request.GET.get("name")
    return serve_h15_guard_against_a_wider_trusted_root(name)
