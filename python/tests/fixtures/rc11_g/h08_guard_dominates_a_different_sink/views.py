from .helpers import serve_h08_guard_dominates_a_different_sink


def view_h08_guard_dominates_a_different_sink(request):
    name = request.GET.get("name")
    other = request.GET.get("other")
    return serve_h08_guard_dominates_a_different_sink(name, other)
