from .helpers import serve_v21_guard_method_always_true


def view_v21_guard_method_always_true(request):
    name = request.GET.get("name")
    return serve_v21_guard_method_always_true(name)
