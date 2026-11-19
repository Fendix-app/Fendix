import os


def serve_y07_multipart_join_first_part_root(name):
    target = os.path.realpath(os.path.join("/srv", "uploads", name))
    if not target.startswith(os.path.realpath("/srv") + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
