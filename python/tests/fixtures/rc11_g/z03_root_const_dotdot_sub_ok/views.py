from .helpers import serve_z03_root_const_dotdot_sub_ok


def view_z03_root_const_dotdot_sub_ok(request):
    name = request.GET.get("name")
    return serve_z03_root_const_dotdot_sub_ok(name)
