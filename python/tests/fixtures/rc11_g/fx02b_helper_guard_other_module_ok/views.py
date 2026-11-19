from .helpers import serve_fx02b_helper_guard_other_module_ok


def view_fx02b_helper_guard_other_module_ok(request):
    name = request.GET.get("name")
    return serve_fx02b_helper_guard_other_module_ok(name)
