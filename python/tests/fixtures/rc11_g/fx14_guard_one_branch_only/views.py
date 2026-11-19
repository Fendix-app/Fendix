from .helpers import serve_fx14_guard_one_branch_only


def view_fx14_guard_one_branch_only(request):
    name = request.GET.get("name")
    return serve_fx14_guard_one_branch_only(name)
