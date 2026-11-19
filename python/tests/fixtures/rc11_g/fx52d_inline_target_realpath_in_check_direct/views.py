import os

BASE = "/srv/uploads"


def view_fx52d_inline_target_realpath_in_check_direct(request):
    name = request.GET.get("name")
    target = os.path.join(BASE, name)
    real_root = os.path.realpath(BASE)
    if os.path.commonpath([real_root, os.path.realpath(target)]) != real_root:
        return None
    with open(target, "rb") as fh:
        return fh.read()
