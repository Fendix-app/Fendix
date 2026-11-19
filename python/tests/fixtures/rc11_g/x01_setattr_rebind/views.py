from .helpers import serve_x01_setattr_rebind


def view_x01_setattr_rebind(request):
    name = request.GET.get("name")
    return serve_x01_setattr_rebind(name)
