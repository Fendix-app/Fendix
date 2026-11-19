from .helpers import serve_fx24_inverted_helper


def view_fx24_inverted_helper(request):
    name = request.GET.get("name")
    return serve_fx24_inverted_helper(name)
