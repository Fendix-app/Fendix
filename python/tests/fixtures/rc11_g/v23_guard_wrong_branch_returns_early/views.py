from .helpers import serve_v23_guard_wrong_branch_returns_early


def view_v23_guard_wrong_branch_returns_early(request):
    name = request.GET.get("name")
    return serve_v23_guard_wrong_branch_returns_early(name)
