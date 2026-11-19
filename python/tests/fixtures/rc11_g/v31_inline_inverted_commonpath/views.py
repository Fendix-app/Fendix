from .helpers import serve_v31_inline_inverted_commonpath


def view_v31_inline_inverted_commonpath(request):
    name = request.GET.get("name")
    return serve_v31_inline_inverted_commonpath(name)
