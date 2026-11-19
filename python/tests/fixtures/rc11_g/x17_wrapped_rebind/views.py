from .helpers import serve_x17_wrapped_rebind


def view_x17_wrapped_rebind(request):
    name = request.GET.get("name")
    return serve_x17_wrapped_rebind(name)
