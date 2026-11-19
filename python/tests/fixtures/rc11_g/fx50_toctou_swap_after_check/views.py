from .helpers import serve_fx50_toctou_swap_after_check


def view_fx50_toctou_swap_after_check(request):
    name = request.GET.get("name")
    return serve_fx50_toctou_swap_after_check(name)
