from .helpers import serve_v39_tuple_rebind_after_guard


def view_v39_tuple_rebind_after_guard(request):
    name = request.GET.get("name")
    return serve_v39_tuple_rebind_after_guard(name)
