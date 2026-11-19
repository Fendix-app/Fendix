import os

BASE = "/srv/uploads"


def view_fx55d_startswith_no_sep_direct(request):
    name = request.GET.get("name")
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE):
        return None
    with open(full, "rb") as fh:
        return fh.read()
