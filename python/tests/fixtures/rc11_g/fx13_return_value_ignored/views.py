from .helpers import serve_fx13_return_value_ignored


def view_fx13_return_value_ignored(request):
    name = request.GET.get("name")
    return serve_fx13_return_value_ignored(name)
