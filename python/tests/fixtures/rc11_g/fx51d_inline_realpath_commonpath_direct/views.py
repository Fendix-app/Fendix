import os

BASE = "/srv/uploads"


def view_fx51d_inline_realpath_commonpath_direct(request):
    name = request.GET.get("name")
    full = os.path.realpath(os.path.join(BASE, name))
    if os.path.commonpath([BASE, full]) != BASE:
        return None
    with open(full, "rb") as fh:
        return fh.read()
