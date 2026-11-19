from .helpers import serve_x05_init_patches_guards_attr


def view_x05_init_patches_guards_attr(request):
    name = request.GET.get("name")
    return serve_x05_init_patches_guards_attr(name)
