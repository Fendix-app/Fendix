import os

BASE = "/srv/uploads"


def is_within(root, target):
    return os.path.realpath(target).startswith(os.path.realpath(root))


def serve_fx10s_startswith_no_sep_samefile(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()


def view_fx10s_startswith_no_sep_samefile(request):
    name = request.GET.get("name")
    return serve_fx10s_startswith_no_sep_samefile(name)
