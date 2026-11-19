from .helpers import serve_t03_safe_narrower_root_plain_dir


def view_t03_safe_narrower_root_plain_dir(request):
    name = request.GET.get("name")
    return serve_t03_safe_narrower_root_plain_dir(name)
