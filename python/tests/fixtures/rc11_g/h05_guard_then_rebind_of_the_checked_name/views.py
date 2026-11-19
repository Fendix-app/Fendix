from .helpers import serve_h05_guard_then_rebind_of_the_checked_name


def view_h05_guard_then_rebind_of_the_checked_name(request):
    name = request.GET.get("name")
    return serve_h05_guard_then_rebind_of_the_checked_name(name)
