from .helpers import serve_fx16_decode_after_check


def view_fx16_decode_after_check(request):
    name = request.GET.get("name")
    return serve_fx16_decode_after_check(name)
