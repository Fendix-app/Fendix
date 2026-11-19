from .helpers import serve_z02_helper_root_const_dotdot_after_symlink


def view_z02_helper_root_const_dotdot_after_symlink(request):
    name = request.GET.get("name")
    return serve_z02_helper_root_const_dotdot_after_symlink(name)
