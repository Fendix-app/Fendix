from .helpers import serve_v42_with_as_rebind


def view_v42_with_as_rebind(request):
    name = request.GET.get("name")
    return serve_v42_with_as_rebind(name)
