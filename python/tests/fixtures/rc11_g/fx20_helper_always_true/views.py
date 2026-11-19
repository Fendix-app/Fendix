from .helpers import serve_fx20_helper_always_true


def view_fx20_helper_always_true(request):
    name = request.GET.get("name")
    return serve_fx20_helper_always_true(name)
