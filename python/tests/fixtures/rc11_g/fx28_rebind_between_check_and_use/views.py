from .helpers import serve_fx28_rebind_between_check_and_use


def view_fx28_rebind_between_check_and_use(request):
    name = request.GET.get("name")
    return serve_fx28_rebind_between_check_and_use(name)
