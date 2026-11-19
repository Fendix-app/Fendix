from .helpers import serve_fx17_decode_before_check_ok


def view_fx17_decode_before_check_ok(request):
    name = request.GET.get("name")
    return serve_fx17_decode_before_check_ok(name)
