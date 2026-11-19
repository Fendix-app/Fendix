from .helpers import serve_fx01b_inline_target_realpath_in_check_ok


def view_fx01b_inline_target_realpath_in_check_ok(request):
    name = request.GET.get("name")
    return serve_fx01b_inline_target_realpath_in_check_ok(name)
