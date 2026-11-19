from .helpers import serve_s03_guard_and_sink_in_the_same_branch


def view_s03_guard_and_sink_in_the_same_branch(request):
    name = request.GET.get("name")
    return serve_s03_guard_and_sink_in_the_same_branch(name)
