from .helpers import serve_v38_augassign_after_guard


def view_v38_augassign_after_guard(request):
    name = request.GET.get("name")
    return serve_v38_augassign_after_guard(name)
