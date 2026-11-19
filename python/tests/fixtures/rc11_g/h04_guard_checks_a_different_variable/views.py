from .helpers import serve_h04_guard_checks_a_different_variable


def view_h04_guard_checks_a_different_variable(request):
    name = request.GET.get("name")
    return serve_h04_guard_checks_a_different_variable(name)
