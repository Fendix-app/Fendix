from .helpers import serve_h03_guard_on_one_branch_only


def view_h03_guard_on_one_branch_only(request):
    name = request.GET.get("name")
    return serve_h03_guard_on_one_branch_only(name)
