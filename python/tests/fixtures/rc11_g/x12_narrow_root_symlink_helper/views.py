from .helpers import serve_x12_narrow_root_symlink_helper


def view_x12_narrow_root_symlink_helper(request):
    name = request.GET.get("name")
    return serve_x12_narrow_root_symlink_helper(name)
