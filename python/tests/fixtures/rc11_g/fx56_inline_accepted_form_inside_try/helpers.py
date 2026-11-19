import os

BASE = "/srv/uploads"


def serve_fx56_inline_accepted_form_inside_try(name):
    try:
        full = os.path.realpath(os.path.join(BASE, name))
        if os.path.commonpath([BASE, full]) != BASE:
            return None
        with open(full, "rb") as fh:
            return fh.read()
    except OSError:
        return None
