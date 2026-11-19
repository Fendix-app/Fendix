import os

BASE = "/srv/uploads"


def view_fx53d_dotdot_isabs_direct(request):
    name = request.GET.get("name")
    if ".." in name or os.path.isabs(name):
        return None
    with open(os.path.join(BASE, name), "rb") as fh:
        return fh.read()
