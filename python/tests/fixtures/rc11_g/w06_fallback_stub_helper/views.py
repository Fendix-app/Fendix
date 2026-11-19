from .helpers import serve_w06_fallback_stub_helper


def view_w06_fallback_stub_helper(request):
    name = request.GET.get("name")
    return serve_w06_fallback_stub_helper(name)
