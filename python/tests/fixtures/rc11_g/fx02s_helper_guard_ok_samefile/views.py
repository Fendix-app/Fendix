import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_fx02s_helper_guard_ok_samefile(name):
    target = os.path.join(BASE, name)
    if not _path_is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()


def view_fx02s_helper_guard_ok_samefile(request):
    name = request.GET.get("name")
    return serve_fx02s_helper_guard_ok_samefile(name)
