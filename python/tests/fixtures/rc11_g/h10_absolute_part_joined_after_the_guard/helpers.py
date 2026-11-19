import os

BASE = "/srv/uploads"


def serve_h10_absolute_part_joined_after_the_guard(name):
    folder = os.path.realpath(os.path.join(BASE, "a"))
    if os.path.commonpath([BASE, folder]) != BASE:
        return None
    with open(os.path.join(folder, name), "rb") as fh:
        return fh.read()
