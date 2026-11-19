from .helpers import serve_fx23_commonprefix_helper


def view_fx23_commonprefix_helper(request):
    name = request.GET.get("name")
    return serve_fx23_commonprefix_helper(name)
