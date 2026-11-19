from .helpers import serve_s02_guard_nested_in_with_and_try


def view_s02_guard_nested_in_with_and_try(request):
    name = request.GET.get("name")
    return serve_s02_guard_nested_in_with_and_try(name)
