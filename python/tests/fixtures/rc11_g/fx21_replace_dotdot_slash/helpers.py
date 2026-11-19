import os

BASE = "/srv/uploads"


def serve_fx21_replace_dotdot_slash(name):
    clean = name.replace("../", "")
    with open(os.path.join(BASE, clean), "rb") as fh:
        return fh.read()
