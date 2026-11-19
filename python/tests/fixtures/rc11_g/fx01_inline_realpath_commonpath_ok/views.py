from .helpers import serve_fx01_inline_realpath_commonpath_ok


def view_fx01_inline_realpath_commonpath_ok(request):
    name = request.GET.get("name")
    return serve_fx01_inline_realpath_commonpath_ok(name)
